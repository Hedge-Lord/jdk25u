#include "services/profileCheckpoint.hpp"
#include "utilities/ostream.hpp"
#include "classfile/systemDictionary.hpp"
#include "classfile/symbolTable.hpp"
#include "classfile/classLoaderDataGraph.hpp"
#include "services/profileCheckpoint_globals.hpp"
#include "oops/instanceKlass.hpp"
#include "oops/methodData.hpp"
#include "oops/method.hpp"
#include "oops/methodCounters.hpp"
#include "oops/klass.inline.hpp"
#include "runtime/handles.inline.hpp"
#include "logging/log.hpp"
#include "utilities/copy.hpp"
#include "runtime/os.hpp"
#include "runtime/globals.hpp"
#include "runtime/deoptimization.hpp"
#include "compiler/compilationPolicy.hpp"
#include "compiler/compileBroker.hpp"
#include "compiler/compilerDefinitions.hpp"
#include "memory/resourceArea.hpp"
#include <cstdio>
#include <cstring>

// ---- helpers (extracted for readability) ----

static bool copy_mdo_payload(MethodData* dst_mdo, const char* src_bytes, u4 src_size) {
  if (dst_mdo == nullptr) return false;
  if ((u4)dst_mdo->size_in_bytes() != src_size) return false;
  address dst_base = dst_mdo->data_base();
  const size_t data_sz  = (size_t)dst_mdo->data_size();
  const size_t data_off = (size_t)(dst_base - (address)dst_mdo);
  const char* src = src_bytes + data_off;
  Copy::conjoint_jbytes(src, (char*)dst_base, (jlong)data_sz);
  return true;
}

static void print_mdo_header(MethodData* mdo, outputStream* st = tty) {
  if (mdo == nullptr) {
    st->print_cr("  (MethodData is null)");
    return;
  }
  ResourceMark rm;
  Method* m = mdo->method();
  const char* method_name = (m != nullptr) ? m->name_and_sig_as_C_string() : "<null>";
  const char* holder_name = (m != nullptr && m->method_holder() != nullptr) ? m->method_holder()->external_name() : "<null>";
  st->print_cr("  method=%s holder=%s", method_name, holder_name);
  st->print_cr("  size_in_bytes=%d data_size=%d extra_data_size=%d",
               mdo->size_in_bytes(),
               mdo->data_size(),
               mdo->extra_data_size());
  st->print_cr("  parameters_type_data_di=%d exception_handler_data_di=%d",
               mdo->parameters_type_data_di(),
               mdo->exception_handlers_data_di());
  st->print_cr("  invocation_counter=%d start=%d delta=%d",
               mdo->invocation_count(),
               mdo->invocation_count_start(),
               mdo->invocation_count_delta());
  st->print_cr("  backedge_counter=%d start=%d delta=%d",
               mdo->backedge_count(),
               mdo->backedge_count_start(),
               mdo->backedge_count_delta());
  st->print_cr("  tenure_traps=%u decompile_count=%u overflow_recompiles=%u overflow_traps=%u",
               mdo->tenure_traps(),
               mdo->decompile_count(),
               mdo->overflow_recompile_count(),
               mdo->overflow_trap_count());
  st->print_cr("  loops=%d blocks=%d mature=%s would_profile=%s",
               mdo->num_loops(),
               mdo->num_blocks(),
               mdo->is_mature() ? "true" : "false",
               mdo->would_profile() ? "true" : "false");
  st->print_cr("  escape_flags=0x%lx arg_local=0x%lx arg_stack=0x%lx arg_returned=0x%lx",
               (long)mdo->eflags(),
               (long)mdo->arg_local(),
               (long)mdo->arg_stack(),
               (long)mdo->arg_returned());

  st->print("  trap_counts:");
  bool printed = false;
  const uint reason_limit = MethodData::trap_reason_limit();
  for (uint reason = 0; reason < reason_limit; reason++) {
    uint count = mdo->trap_count((int)reason);
    if (count == 0) {
      continue;
    }
    st->print(" %s=%u", Deoptimization::trap_reason_name(reason), count);
    printed = true;
  }
  if (!printed) {
    st->print(" (none)");
  }
  st->cr();
}

static ProfileCheckpoint::LoaderId loader_id_from_loader(ClassLoaderData* cld) {
  if (cld == nullptr || cld->is_boot_class_loader_data()) return ProfileCheckpoint::LoaderId::BOOT;
  if (cld->is_platform_class_loader_data()) return ProfileCheckpoint::LoaderId::PLATFORM;
  if (cld->is_system_class_loader_data()) return ProfileCheckpoint::LoaderId::SYSTEM;
  return ProfileCheckpoint::LoaderId::UNDEFINED;
}

static Handle loader_handle_from_loader(ProfileCheckpoint::LoaderId loader_id, TRAPS) {
  switch (loader_id) {
    case ProfileCheckpoint::LoaderId::BOOT: return Handle();
    case ProfileCheckpoint::LoaderId::PLATFORM: return Handle(THREAD, SystemDictionary::java_platform_loader());
    case ProfileCheckpoint::LoaderId::SYSTEM: return Handle(THREAD, SystemDictionary::java_system_loader());
    default: return Handle();
  }
}

static InstanceKlass* resolve_klass_utf8(const char* name, ProfileCheckpoint::LoaderId loader_id, TRAPS) {
  Symbol* sym = SymbolTable::new_symbol(name);
  Handle loader = loader_handle_from_loader(loader_id, THREAD);
  Klass* k = SystemDictionary::resolve_or_fail(sym, loader, true, THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; return nullptr; }
  return (k != nullptr && k->is_instance_klass()) ? InstanceKlass::cast(k) : nullptr;
}

static Method* resolve_method_utf8(InstanceKlass* ik, const char* mname, const char* msig) {
  if (ik == nullptr) return nullptr;
  Symbol* mn = SymbolTable::new_symbol(mname);
  Symbol* sg = SymbolTable::new_symbol(msig);
  return ik->find_method(mn, sg);
}

static void sanitize_type_entries(MethodData* mdo) {
  for (ProfileData* pd = mdo->first_data(); mdo->is_valid(pd); pd = mdo->next_data(pd)) {
    if (pd->is_VirtualCallData() || pd->is_ReceiverTypeData()) {
      ReceiverTypeData* rtd = pd->as_ReceiverTypeData();
      for (uint row = 0; row < rtd->row_limit(); row++) {
        int off_b = in_bytes(ReceiverTypeData::receiver_offset(row));
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
      }
    }
    if (pd->is_CallTypeData()) {
      CallTypeData* ctd = (CallTypeData*)pd;
      if (ctd->has_arguments()) {
        for (int ai = 0; ai < ctd->number_of_arguments(); ai++) {
          int off_b = in_bytes(ctd->argument_type_offset(ai));
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
        }
      }
      if (ctd->has_return()) {
        int off_b = in_bytes(ctd->return_type_offset());
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
      }
    }
    if (pd->is_VirtualCallTypeData()) {
      VirtualCallTypeData* vctd = pd->as_VirtualCallTypeData();
      if (vctd->has_arguments()) {
        for (int ai = 0; ai < vctd->number_of_arguments(); ai++) {
          int off_b = in_bytes(vctd->argument_type_offset(ai));
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
        }
      }
      if (vctd->has_return()) {
        int off_b = in_bytes(vctd->return_type_offset());
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
      }
    }
  }
  if (ParametersTypeData* p = mdo->parameters_type_data()) {
    address p_dp = p->dp();
    for (int pi = 0; pi < p->number_of_parameters(); pi++) {
      int off_b = in_bytes(ParametersTypeData::type_offset(pi));
      intptr_t* cell = (intptr_t*)(p_dp + off_b);
      *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
    }
  }
}

static void collect_type_fixups(MethodData* mdo,
                                ProfileCheckpoint::SymtabBuilder& stb,
                                GrowableArray<ProfileCheckpoint::Fixup>& out_fixups) {
  for (ProfileData* pd = mdo->first_data(); mdo->is_valid(pd); pd = mdo->next_data(pd)) {
    if (pd->is_VirtualCallData() || pd->is_ReceiverTypeData()) {
      ReceiverTypeData* rtd = pd->as_ReceiverTypeData();
      for (uint row = 0; row < rtd->row_limit(); row++) {
        int off_b = in_bytes(ReceiverTypeData::receiver_offset(row));
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        Klass* k = TypeEntries::valid_klass(*cell);
        if (k != nullptr && k->is_instance_klass()) {
          const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
          ProfileCheckpoint::Fixup fx;
          fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS;
          fx.target.id = stb.intern(cname);
          fx.loader = loader_id_from_loader(k->class_loader_data());
          out_fixups.append(fx);
        }
      }
    }
    if (pd->is_CallTypeData()) {
      CallTypeData* ctd = (CallTypeData*)pd;
      if (ctd->has_arguments()) {
        for (int ai = 0; ai < ctd->number_of_arguments(); ai++) {
          int off_b = in_bytes(ctd->argument_type_offset(ai));
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          Klass* k = TypeEntries::valid_klass(*cell);
          if (k != nullptr && k->is_instance_klass()) {
            const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
            ProfileCheckpoint::Fixup fx;
            fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
            fx.kind = ProfileCheckpoint::FixupKind::KLASS;
            fx.target.id = stb.intern(cname);
            fx.loader = loader_id_from_loader(k->class_loader_data());
            out_fixups.append(fx);
          }
        }
      }
      if (ctd->has_return()) {
        int off_b = in_bytes(ctd->return_type_offset());
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        Klass* k = TypeEntries::valid_klass(*cell);
        if (k != nullptr && k->is_instance_klass()) {
          const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
          ProfileCheckpoint::Fixup fx;
          fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS;
          fx.target.id = stb.intern(cname);
          fx.loader = loader_id_from_loader(k->class_loader_data());
          out_fixups.append(fx);
        }
      }
    }
    if (pd->is_VirtualCallTypeData()) {
      VirtualCallTypeData* vctd = pd->as_VirtualCallTypeData();
      if (vctd->has_arguments()) {
        for (int ai = 0; ai < vctd->number_of_arguments(); ai++) {
          int off_b = in_bytes(vctd->argument_type_offset(ai));
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          Klass* k = TypeEntries::valid_klass(*cell);
          if (k != nullptr && k->is_instance_klass()) {
            const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
            ProfileCheckpoint::Fixup fx;
            fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
            fx.kind = ProfileCheckpoint::FixupKind::KLASS;
            fx.target.id = stb.intern(cname);
            fx.loader = loader_id_from_loader(k->class_loader_data());
            out_fixups.append(fx);
          }
        }
      }
      if (vctd->has_return()) {
        int off_b = in_bytes(vctd->return_type_offset());
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        Klass* k = TypeEntries::valid_klass(*cell);
        if (k != nullptr && k->is_instance_klass()) {
          const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
          ProfileCheckpoint::Fixup fx;
          fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS;
          fx.target.id = stb.intern(cname);
          fx.loader = loader_id_from_loader(k->class_loader_data());
          out_fixups.append(fx);
        }
      }
    }
  }
  if (ParametersTypeData* p = mdo->parameters_type_data()) {
    address p_dp = p->dp();
    for (int pi = 0; pi < p->number_of_parameters(); pi++) {
      int off_b = in_bytes(ParametersTypeData::type_offset(pi));
      intptr_t* cell = (intptr_t*)(p_dp + off_b);
      Klass* k = TypeEntries::valid_klass(*cell);
      if (k != nullptr && k->is_instance_klass()) {
        const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
        ProfileCheckpoint::Fixup fx;
        fx.offset_in_mdo = (u4)((p_dp + off_b) - (address)mdo);
        fx.kind = ProfileCheckpoint::FixupKind::KLASS;
        fx.target.id = stb.intern(cname);
        fx.loader = loader_id_from_loader(k->class_loader_data());
        out_fixups.append(fx);
      }
    }
  }
}

static void apply_fixups(MethodData* mdo,
                         const ProfileCheckpoint::Fixup* fixups,
                         u4 fixup_count,
                         GrowableArray<char*>& symtab,
                         TRAPS) {
  for (u4 fi = 0; fi < fixup_count; fi++) {
    const ProfileCheckpoint::Fixup& fx = fixups[fi];
    if (fx.kind != ProfileCheckpoint::FixupKind::KLASS) {
      log_debug(compilation)("MDO checkpoint: unsupported fixup kind=%d at off=%u sym_id=%u",
                             (int)fx.kind, fx.offset_in_mdo, fx.target.id);
      continue;
    }
    if ((int)fx.target.id < 0 || (int)fx.target.id >= symtab.length()) {
      log_debug(compilation)("MDO checkpoint: invalid sym_id=%u (symtab_len=%d) at off=%u",
                             fx.target.id, symtab.length(), fx.offset_in_mdo);
      continue;
    }
    const char* cname = symtab.at((int)fx.target.id);
    InstanceKlass* k = resolve_klass_utf8(cname, fx.loader, THREAD);
    if (k != nullptr) {
      address cell_addr = (address)mdo + fx.offset_in_mdo;
      intptr_t* cell = (intptr_t*)cell_addr;
      *cell = TypeEntries::with_status(InstanceKlass::cast(k), *cell);
    } else {
      log_debug(compilation)("MDO checkpoint: fixup unresolved %s (loader=%d) at off=%u",
                             cname, (int)fx.loader, fx.offset_in_mdo);
    }
  }
}

static bool write_exact(fileStream* out, const void* p, size_t n) {
  if (n == 0) return true;
  out->write((const char*)p, n);
  return true;
}

static bool read_exact(FILE* in, void* p, size_t n) {
  return ::fread(p, 1, n, in) == n;
}

static bool write_u4(fileStream* out, u4 v) {
  return write_exact(out, &v, sizeof(v));
}

static bool read_u4(FILE* in, u4& v) {
  return read_exact(in, &v, sizeof(v));
}

static char* read_str(FILE* in) {
  u4 len = 0;
  if (!read_u4(in, len)) return nullptr;
  char* buf = (char*)os::malloc(len + 1, mtInternal);
  if (buf == nullptr) return nullptr;
  if (len > 0 && !read_exact(in, buf, len)) { os::free(buf); return nullptr; }
  buf[len] = '\0';
  return buf;
}

static bool write_u2(fileStream* out, u2 v) { return write_exact(out, &v, sizeof(v)); }
static bool read_u2(FILE* in, u2& v) { return read_exact(in, &v, sizeof(v)); }

bool ProfileCheckpoint::Header::write(fileStream* out, const Header& h) {
  if (!write_exact(out, h.magic, sizeof(h.magic))) return false;
  if (!write_u2(out, h.pointer_size)) return false;
  if (!write_u2(out, h.endianness)) return false;
  if (!write_exact(out, &h.layout, sizeof(h.layout))) return false;
  if (!write_u4(out, h.sym_count)) return false;
  if (!write_u4(out, h.rec_count)) return false;
  return true;
}

bool ProfileCheckpoint::Header::read(FILE* in, Header& h) {
  if (!read_exact(in, h.magic, sizeof(h.magic))) return false;
  if (h.magic[0] != 'M' || h.magic[1] != 'D' || h.magic[2] != 'O' || h.magic[3] != 'X') return false;
  if (!read_u2(in, h.pointer_size)) return false;
  if (!read_u2(in, h.endianness)) return false;
  if (!read_exact(in, &h.layout, sizeof(h.layout))) return false;
  if (!read_u4(in, h.sym_count)) return false;
  if (!read_u4(in, h.rec_count)) return false;
  return true;
}
         
static u2 detect_endianness() {
  union { u4 v; u1 b[4]; } u; u.v = 1;
  return (u.b[0] == 1) ? (u2)0 : (u2)1;
}

void ProfileCheckpoint::Header::init(Header& h, u4 sym_count, u4 rec_count) {
  h.magic[0] = 'M'; h.magic[1] = 'D'; h.magic[2] = 'O'; h.magic[3] = 'X';
  h.pointer_size = (u2)sizeof(void*);
  h.endianness = detect_endianness();
  h.layout.type_profile_level = (uint32_t)TypeProfileLevel;
  h.layout.type_profile_args_limit = (int32_t)TypeProfileArgsLimit;
  h.layout.type_profile_parms_limit = (int32_t)TypeProfileParmsLimit;
  h.layout.type_profile_width = (int64_t)TypeProfileWidth;
  h.layout.profile_traps = (uint8_t)(ProfileTraps ? 1 : 0);
  h.layout.type_profile_casts = (uint8_t)(TypeProfileCasts ? 1 : 0);
  h.layout.spec_trap_limit_extra_entries = (int32_t)SpecTrapLimitExtraEntries;
  h.sym_count = sym_count;
  h.rec_count = rec_count;
}

bool ProfileCheckpoint::Record::write(fileStream* out, const Record& r, const void* mdo_bytes, const Fixup* fixups, const void* mc_bytes, const void* header_bytes) {
  if (!write_u4(out, r.key.klass.id)) return false;
  if (!write_u4(out, r.key.name.id))  return false;
  if (!write_u4(out, r.key.sig.id))   return false;
  u1 loader = (u1)r.key.loader;
  if (!write_exact(out, &loader, sizeof(loader))) return false;
  if (!write_exact(out, &r.comp_level, sizeof(r.comp_level))) return false;
  if (!write_u4(out, r.mdo_size)) return false;
  if (!write_u4(out, r.fixup_count)) return false;
  for (u4 i = 0; i < r.fixup_count; i++) {
    if (!write_u4(out, fixups[i].offset_in_mdo)) return false;
    u1 kind = (u1)fixups[i].kind;
    if (!write_exact(out, &kind, sizeof(kind))) return false;
    if (!write_u4(out, fixups[i].target.id)) return false;
  }
  if (!write_exact(out, mdo_bytes, r.mdo_size)) return false;
  if (!write_u4(out, r.header_size)) return false;
  if (r.header_size > 0) {
    if (!write_exact(out, header_bytes, r.header_size)) return false;
  }
  if (!write_u4(out, r.mc_size)) return false;
  if (r.mc_size > 0) {
    if (!write_exact(out, mc_bytes, r.mc_size)) return false;
  }
  return true;
}

bool ProfileCheckpoint::Record::read(FILE* in, Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes, char*& header_bytes) {
  if (!read_u4(in, r.key.klass.id)) return false;
  if (!read_u4(in, r.key.name.id))  return false;
  if (!read_u4(in, r.key.sig.id))   return false;
  u1 loader = 0;
  if (!read_exact(in, &loader, sizeof(loader))) return false;
  r.key.loader = (LoaderId)loader;
  if (!read_exact(in, &r.comp_level, sizeof(r.comp_level))) return false;
  if (!read_u4(in, r.mdo_size)) return false;
  if (!read_u4(in, r.fixup_count)) return false;
  fixups = nullptr;
  if (r.fixup_count > 0) {
    fixups = (Fixup*)os::malloc(sizeof(Fixup) * r.fixup_count, mtInternal);
    if (fixups == nullptr) return false;
    for (u4 i = 0; i < r.fixup_count; i++) {
      u1 kind = 0;
      if (!read_u4(in, fixups[i].offset_in_mdo)) { os::free(fixups); return false; }
      if (!read_exact(in, &kind, sizeof(kind))) { os::free(fixups); return false; }
      fixups[i].kind = (FixupKind)kind;
      if (!read_u4(in, fixups[i].target.id)) { os::free(fixups); return false; }
    }
  }
  mdo_bytes = nullptr;
  if (r.mdo_size > 0) {
    mdo_bytes = (char*)os::malloc(r.mdo_size, mtInternal);
    if (mdo_bytes == nullptr) { if (fixups) os::free(fixups); return false; }
    if (!read_exact(in, mdo_bytes, r.mdo_size)) { os::free(mdo_bytes); if (fixups) os::free(fixups); return false; }
  }
  header_bytes = nullptr;
  if (!read_u4(in, r.header_size)) {
    if (fixups) os::free(fixups);
    if (mdo_bytes) os::free(mdo_bytes);
    return false;
  }
  if (r.header_size > 0) {
    header_bytes = (char*)os::malloc(r.header_size, mtInternal);
    if (header_bytes == nullptr) {
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      return false;
    }
    if (!read_exact(in, header_bytes, r.header_size)) {
      os::free(header_bytes);
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      return false;
    }
  }
  if (!read_u4(in, r.mc_size)) return false;
  mc_bytes = nullptr;
  if (r.mc_size > 0) {
    mc_bytes = (char*)os::malloc(r.mc_size, mtInternal);
    if (mc_bytes == nullptr) {
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      if (header_bytes) os::free(header_bytes);
      return false;
    }
    if (!read_exact(in, mc_bytes, r.mc_size)) {
      os::free(mc_bytes);
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      if (header_bytes) os::free(header_bytes);
      return false;
    }
  }
  return true;
}

ProfileCheckpoint::Loader::Loader(JavaThread* thread)
  : _thread(thread),
    _records_read(0),
    _records_installed(0),
    _size_mismatch(0) {}

const char* ProfileCheckpoint::Loader::load_status_name(LoadStatus status) {
  switch (status) {
    case LoadStatus::Success:          return "success";
    case LoadStatus::MissingPath:      return "missing_path";
    case LoadStatus::FileOpenFailed:   return "file_open_failed";
    case LoadStatus::HeaderInvalid:    return "header_invalid";
    case LoadStatus::SymtabReadFailed: return "symtab_read_failed";
    case LoadStatus::RecordReadFailed: return "record_read_failed";
    default:                           return "unknown";
  }
}

static void trigger_eager_compile(Method* target, u1 stored_level, JavaThread* thread) {
  if (!EagerCompileAfterLoad) return;
  if (target == nullptr || thread == nullptr) return;
  if (!UseCompiler || !CompilationPolicy::is_compilation_enabled()) return;
  if (target->is_abstract() || target->is_native()) return;
  CompLevel level = (CompLevel)stored_level;
  if (level < CompLevel_none) {
    level = CompLevel_none;
  } else if (level > CompLevel_full_optimization) {
    level = CompLevel_full_optimization;
  }
  JavaThread* THREAD = thread; // For exception macros.
  methodHandle mh(THREAD, target);
  log_info(compilation)("Eager compiling %s %s %s at level %u", target->name()->as_utf8(), target->signature()->as_utf8(), target->method_holder()->name()->as_utf8(), level);
  CompileBroker::compile_method(mh, InvocationEntryBci, level, 0, CompileTask::Reason_MustBeCompiled, THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }
}

void ProfileCheckpoint::wait_for_compile_completion(JavaThread* THREAD) {
  if (!UseCompiler || !CompilationPolicy::is_compilation_enabled()) {
    return;
  }

  // Block until compile queues are drained and no active tasks remain.
  for (;;) {
    CompileBroker::wait_for_no_active_tasks();
    CompileQueue* q1 = CompileBroker::c1_compile_queue();
    CompileQueue* q2 = CompileBroker::c2_compile_queue();
    bool empty1 = (q1 == nullptr) || q1->is_empty();
    bool empty2 = (q2 == nullptr) || q2->is_empty();
    if (empty1 && empty2) break;
    os::naked_short_sleep(1);
  }
  log_info(compilation)("Eager compilation completed");
}

bool ProfileCheckpoint::Loader::install_record(const Record& rec,
                                               Fixup* fixups,
                                               char* mdo_bytes,
                                               char* mc_bytes,
                                               char* header_bytes,
                                               GrowableArray<char*>& symtab) {
  JavaThread* THREAD = _thread; // For exception macros.
  const char* kname = symtab.at((int)rec.key.klass.id);
  const char* mname = symtab.at((int)rec.key.name.id);
  const char* msig  = symtab.at((int)rec.key.sig.id);

  InstanceKlass* holder = resolve_klass_utf8(kname, rec.key.loader, THREAD);
  if (holder == nullptr) {
    log_debug(compilation)("MDO checkpoint: resolve class failed for %s", kname);
    return false;
  }
  Method* target = resolve_method_utf8(holder, mname, msig);
  if (target == nullptr) {
    log_debug(compilation)("MDO checkpoint: resolve method failed for %s %s %s", kname, mname, msig);
    return false;
  }

  holder->link_class(THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }

  if (target->method_data() == nullptr) {
    methodHandle mh(THREAD, target);
    target->build_profiling_method_data(mh, THREAD);
    if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }
  }

  MethodData* mdo = target->method_data();
  if (mdo == nullptr) {
    log_debug(compilation)("MDO checkpoint: MethodData allocation/build failed for %s %s %s", kname, mname, msig);
    return false;
  }

  if (!copy_mdo_payload(mdo, mdo_bytes, rec.mdo_size)) {
    log_debug(compilation)("MDO checkpoint: copy payload failed for %s %s %s (size=%u)", kname, mname, msig, rec.mdo_size);
    _size_mismatch++;
    return false;
  }

  if (header_bytes != nullptr) {
    if (rec.header_size == sizeof(MethodData::HeaderSnapshot)) {
      MethodData::HeaderSnapshot snapshot;
      Copy::conjoint_jbytes(header_bytes, (char*)&snapshot, rec.header_size);
      if (!mdo->restore_header(snapshot)) {
        log_debug(compilation)("MDO checkpoint: header restore mismatch for %s %s %s", kname, mname, msig);
      }
    } else {
      log_debug(compilation)("MDO checkpoint: header size mismatch for %s %s %s (rec=%u expected=%zu)",
                             kname, mname, msig, rec.header_size, sizeof(MethodData::HeaderSnapshot));
    }
  }

  sanitize_type_entries(mdo);
  if (fixups != nullptr && rec.fixup_count > 0) {
    apply_fixups(mdo, fixups, rec.fixup_count, symtab, THREAD);
  }

  _records_installed++;

  if (rec.mc_size > 0) {
    MethodCounters* mc = target->method_counters();
    if (mc == nullptr) {
      methodHandle mh(THREAD, target);
      MethodCounters* ensured = Method::build_method_counters(THREAD, target);
      if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }
      mc = ensured;
    }
    if (mc != nullptr) {
      const size_t ic_sz = sizeof(InvocationCounter);
      if (rec.mc_size >= ic_sz * 2 + sizeof(jlong) + sizeof(float) + sizeof(jint)) {
        char* p = mc_bytes;
        Copy::conjoint_jbytes(p, (char*)mc->invocation_counter(), (jlong)ic_sz); p += ic_sz;
        Copy::conjoint_jbytes(p, (char*)mc->backedge_counter(), (jlong)ic_sz); p += ic_sz;
        jlong prev_time = *(jlong*)p; p += sizeof(jlong);
        mc->set_prev_time(prev_time);
        float rate = *(float*)p; p += sizeof(float);
        mc->set_rate(rate);
        jint pec = *(jint*)p; p += sizeof(jint);
        mc->set_prev_event_count(pec);
      }
    }
  }

  trigger_eager_compile(target, rec.comp_level, THREAD);

  if (PrintMDOAfterLoad) {
    tty->print_cr("[AfterLoad] %s %s %s", kname, mname, msig);
    tty->print_cr("[MethodDataHeader]");
    print_mdo_header(mdo);
    tty->print_cr("[MethodData]");
    mdo->print_data_on(tty);
    tty->print_cr("[MethodCounters]");
    MethodCounters* mc = target->method_counters();
    if (mc != nullptr) {
      mc->print_data_on(tty);
    } else {
      tty->print_cr("  (none)");
    }
  }

  return true;
}

ProfileCheckpoint::Loader::LoadResult ProfileCheckpoint::Loader::load_from_file(const char* path) {
  LoadResult result{LoadStatus::MissingPath, 0, 0, 0};
  if (path == nullptr) {
    return result;
  }

  FILE* f = os::fopen(path, "rb");
  if (f == nullptr) {
    result.status = LoadStatus::FileOpenFailed;
    return result;
  }

  ResourceMark rm;
  BinaryStreamReader reader(f);

  Header hdr;
  if (!reader.read_header(hdr)) {
    fclose(f);
    result.status = LoadStatus::HeaderInvalid;
    return result;
  }
  u4 sym_count = hdr.sym_count;
  u4 rec_total = hdr.rec_count;
  GrowableArray<char*> symtab((int)sym_count);
  if (!reader.read_symtab(symtab, sym_count)) {
    fclose(f);
    result.status = LoadStatus::SymtabReadFailed;
    return result;
  }

  result.status = LoadStatus::Success;

  for (u4 i = 0; i < rec_total; i++) {
    Record rec;
    Fixup* fixups = nullptr;
    char* mdo_bytes = nullptr;
    char* mc_bytes = nullptr;
    char* header_bytes = nullptr;
    if (!reader.read_record(rec, fixups, mdo_bytes, mc_bytes, header_bytes)) {
      log_debug(compilation)("MDO checkpoint: record read failed at %u", i);
      result.status = LoadStatus::RecordReadFailed;
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      if (mc_bytes) os::free(mc_bytes);
      if (header_bytes) os::free(header_bytes);
      break;
    }

    _records_read++;

    if (rec.mdo_size == 0) {
      log_debug(compilation)("MDO checkpoint: empty MDO payload for sym ids %u %u %u",
                             rec.key.klass.id, rec.key.name.id, rec.key.sig.id);
      if (fixups) os::free(fixups);
      if (mdo_bytes) os::free(mdo_bytes);
      if (mc_bytes) os::free(mc_bytes);
      continue;
    }

    install_record(rec, fixups, mdo_bytes, mc_bytes, header_bytes, symtab);

    if (fixups != nullptr) os::free(fixups);
    if (mdo_bytes != nullptr) os::free(mdo_bytes);
    if (mc_bytes != nullptr) os::free(mc_bytes);
    if (header_bytes != nullptr) os::free(header_bytes);
  }

  fclose(f);

  result.records_read = _records_read;
  result.records_installed = _records_installed;
  result.size_mismatch = _size_mismatch;
  return result;
}

// Build RecMeta (holder/name/sig/mdo size/pointer) for a method with an MDO
static ProfileCheckpoint::RecMeta make_rec_meta_for_method(Method* m) {
  ProfileCheckpoint::RecMeta r{};
  MethodData* mdo = m->method_data();
  // Caller guarantees mdo != nullptr
  MutexLocker ml(mdo->extra_data_lock(), Mutex::_no_safepoint_check_flag);
  InstanceKlass* holder = m->method_holder();
  r.kname = holder->name()->as_utf8();
  r.mname = m->name()->as_utf8();
  r.sig   = m->signature()->as_utf8();
  r.mdo_size = (u4)mdo->size_in_bytes();
  r.mdo_ptr  = (const void*)mdo;
  r.comp_level = (u1)CompLevel_none;
  if (UseCompiler) {
    CompLevel level = CompLevel_none;
    nmethod* code = m->code();
    if (code != nullptr && code->is_in_use()) {
      level = (CompLevel)code->comp_level();
    } else {
      level = (CompLevel)m->highest_comp_level();
    }
    if (level < CompLevel_none) {
      level = CompLevel_none;
    } else if (level > CompLevel_full_optimization) {
      level = CompLevel_full_optimization;
    }
    r.comp_level = (u1)level;
  }
  return r;
}

// Get all methods with MDO data
GrowableArray<Method*> get_methods() {
  GrowableArray<Method*> methods(1024);
  static GrowableArray<Method*>* g_methods;
  g_methods = &methods;
  auto collect_with_mdo = [](Method* m) {
    if (m != nullptr && m->method_data() != nullptr) {
      g_methods->push(m);
    }
  };
  ClassLoaderDataGraph::methods_do(collect_with_mdo);
  return methods;
}

u4 ProfileCheckpoint::SymtabBuilder::intern(const char* s) {
  assert(!_frozen, "frozen");
  for (int i = 0; i < _syms.length(); i++) {
    if (strcmp(_syms.at(i), s) == 0) return (u4)i;
  }
  _syms.append(s);
  return (u4)(_syms.length() - 1);
}

u4 ProfileCheckpoint::SymtabBuilder::id_of(const char* s) const {
  assert(_frozen, "must freeze before lookups");
  for (int i = 0; i < _syms.length(); i++) {
    if (strcmp(_syms.at(i), s) == 0) return (u4)i;
  }
  assert(false, "symbol not found in symtab");
  return (u4)UINT_MAX;
}

bool ProfileCheckpoint::BinaryStreamWriter::write_header(u4 sym_count, u4 rec_count) {
  Header h;
  Header::init(h, sym_count, rec_count);
  return Header::write(_out, h);
}

bool ProfileCheckpoint::BinaryStreamWriter::write_symtab(const GrowableArray<const char*>& symbols) const {
  for (int i = 0; i < symbols.length(); i++) {
    const char* s = symbols.at(i);
    u4 len = (u4)strlen(s);
    if (!write_u4(_out, len)) return false;
    if (!write_exact(_out, s, len)) return false;
  }
  return true;
}

bool ProfileCheckpoint::BinaryStreamWriter::write_record(const Record& r, const void* mdo_bytes,
                                                         const Fixup* fixups, const void* mc_bytes, const void* header_bytes) const {
  return Record::write(_out, r, mdo_bytes, fixups, mc_bytes, header_bytes);
}

bool ProfileCheckpoint::BinaryStreamReader::read_header(Header& h) const {
  return Header::read(_in, h);
}

bool ProfileCheckpoint::BinaryStreamReader::read_symtab(GrowableArray<char*>& symbols, u4 expected) const {
  for (u4 si = 0; si < expected; si++) {
    char* s = read_str(_in);
    if (s == nullptr) {
      return false;
    }
    symbols.append(s);
  }
  return true;
}

bool ProfileCheckpoint::BinaryStreamReader::read_record(Record& r, Fixup*& fixups,
                                                        char*& mdo_bytes, char*& mc_bytes,
                                                        char*& header_bytes) const {
  return Record::read(_in, r, fixups, mdo_bytes, mc_bytes, header_bytes);
}

void ProfileCheckpoint::load(JavaThread* THREAD) {
  if (!LoadMDOAtStartup || MDOReplayLoadFile == nullptr) return;
  Loader loader(THREAD);
  log_info(compilation)("MDO checkpoint: initiating load from %s", MDOReplayLoadFile);
  Loader::LoadResult res = loader.load_from_file(MDOReplayLoadFile);
  if (res.ok()) {
    log_info(compilation)("MDO checkpoint: loaded %d records (%d installed, %d size mismatch)",
                          res.records_read, res.records_installed, res.size_mismatch);
    wait_for_compile_completion(THREAD);
  } else {
    log_warning(compilation)("MDO checkpoint: load failed (status=%s, read=%d, installed=%d, mismatches=%d)",
                             Loader::load_status_name(res.status),
                             res.records_read,
                             res.records_installed,
                             res.size_mismatch);
  }
}

bool ProfileCheckpoint::Loader::dump_to_stream(fileStream* out) {
  if (out == nullptr) {
    return false;
  }

  ResourceMark rm;
  GrowableArray<Method*> methods = get_methods();
  SymtabBuilder stb;
  GrowableArray<RecMeta> recs(1024);

  for (int i = 0; i < methods.length(); i++) {
    Method* m = methods.at(i);
    if (m->method_data() == nullptr) continue;
    recs.append(make_rec_meta_for_method(m));
  }

  GrowableArray< GrowableArray<Fixup>* > fixups_per_rec(recs.length());
  for (int ri = 0; ri < recs.length(); ri++) {
    Method* m = methods.at(ri);
    MethodData* mdo = m->method_data();
    GrowableArray<Fixup>* fx = new GrowableArray<Fixup>(16);
    collect_type_fixups(mdo, stb, *fx);
    fixups_per_rec.append(fx);
  }

  for (int ri = 0; ri < recs.length(); ri++) {
    stb.intern(recs.at(ri).kname);
    stb.intern(recs.at(ri).mname);
    stb.intern(recs.at(ri).sig);
  }
  stb.freeze();

  BinaryStreamWriter writer(out);
  if (!writer.write_header(stb.length(), (u4)recs.length())) {
    return false;
  }
  if (!writer.write_symtab(stb.symbols())) {
    return false;
  }

  u4 emitted = 0;
  for (int ri = 0; ri < recs.length(); ri++) {
    const RecMeta& rn = recs.at(ri);
    Method* m = methods.at(ri);
    MethodData* mdo = m->method_data();
    Record rec;

    rec.key.loader = loader_id_from_loader(m->method_holder()->class_loader_data());
    rec.key.klass.id = stb.id_of(rn.kname);
    rec.key.name.id  = stb.id_of(rn.mname);
    rec.key.sig.id   = stb.id_of(rn.sig);
    rec.key.bytecode_crc32 = 0;
    rec.mdo_size = rn.mdo_size;
    rec.comp_level = rn.comp_level;
    GrowableArray<Fixup>* fx_entries = fixups_per_rec.at(ri);
    rec.fixup_count = (u4)fx_entries->length();

    const void* mc_bytes = nullptr;
    MethodData::HeaderSnapshot header_snapshot;
    mdo->snapshot_header(&header_snapshot);
    rec.header_size = sizeof(header_snapshot);
    const void* header_bytes = &header_snapshot;
    GrowableArray<char> mc_buf(0);
    MethodCounters* mc = m->method_counters();
    if (mc != nullptr) {
      const size_t ic_sz = sizeof(InvocationCounter);
      const size_t mc_sz = ic_sz * 2 + sizeof(jlong) + sizeof(float) + sizeof(jint);
      for (size_t fill = 0; fill < mc_sz; fill++) mc_buf.append((char)0);
      char* p = mc_buf.adr_at(0);
      Copy::conjoint_jbytes((char*)mc->invocation_counter(), p, (jlong)ic_sz);
      p += ic_sz;
      Copy::conjoint_jbytes((char*)mc->backedge_counter(), p, (jlong)ic_sz);
      p += ic_sz;
      *(jlong*)p = mc->prev_time(); p += sizeof(jlong);
      *(float*)p = mc->rate(); p += sizeof(float);
      *(jint*)p = mc->prev_event_count(); p += sizeof(jint);
      rec.mc_size = (u4)mc_sz;
      mc_bytes = mc_buf.adr_at(0);
    } else {
      rec.mc_size = 0;
    }
    Fixup* fixup_buf = rec.fixup_count ? fx_entries->adr_at(0) : nullptr;
    if (!writer.write_record(rec, rn.mdo_ptr, fixup_buf, mc_bytes, header_bytes)) {
      return false;
    }
    if (PrintMDOAtDump) {
      const char* kname = rn.kname;
      const char* mname = rn.mname;
      const char* sig   = rn.sig;
      u1 comp_level = rn.comp_level;
      tty->print_cr("[Dump] %s %s %s %u", kname, mname, sig, comp_level);
      tty->print_cr("[MethodDataHeader]");
      print_mdo_header(mdo);
      tty->print_cr("[MethodData]");
      mdo->print_data_on(tty);
      tty->print_cr("[MethodCounters]");
      MethodCounters* mc_print = m->method_counters();
      if (mc_print != nullptr) {
        mc_print->print_data_on(tty);
      } else {
        tty->print_cr("  (none)");
      }
    }
    emitted++;
  }
  log_info(compilation)("MDO checkpoint: dumped %u MDOs (sym=%u)", emitted, stb.length());
  return true;
}

void ProfileCheckpoint::dump_to_stream(fileStream* out) {
  if (!Loader::dump_to_stream(out)) {
    log_warning(compilation)("MDO checkpoint: dump failed");
  }
}
