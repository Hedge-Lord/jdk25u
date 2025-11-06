#include "services/profileCheckpoint.hpp"
#include "utilities/ostream.hpp"
#include "classfile/systemDictionary.hpp"
#include "classfile/symbolTable.hpp"
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

struct FixupText {
  u4 offset_in_mdo;
  ProfileCheckpoint::FixupKind kind;
  const char* name; // klass internal name
};

static void collect_type_fixups_text(MethodData* mdo, GrowableArray<FixupText>& out_fixups) {
  for (ProfileData* pd = mdo->first_data(); mdo->is_valid(pd); pd = mdo->next_data(pd)) {
    if (pd->is_VirtualCallData() || pd->is_ReceiverTypeData()) {
      ReceiverTypeData* rtd = pd->as_ReceiverTypeData();
      for (uint row = 0; row < rtd->row_limit(); row++) {
        int off_b = in_bytes(ReceiverTypeData::receiver_offset(row));
        intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
        Klass* k = TypeEntries::valid_klass(*cell);
        if (k != nullptr && k->is_instance_klass()) {
          const char* cname = InstanceKlass::cast(k)->name()->as_utf8();
          FixupText fx; fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
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
            FixupText fx; fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
            fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
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
          FixupText fx; fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
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
            FixupText fx; fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
            fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
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
          FixupText fx; fx.offset_in_mdo = (u4)((pd->dp() + off_b) - (address)mdo);
          fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
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
        FixupText fx; fx.offset_in_mdo = (u4)((p_dp + off_b) - (address)mdo);
        fx.kind = ProfileCheckpoint::FixupKind::KLASS; fx.name = cname;
        out_fixups.append(fx);
      }
    }
  }
}

static void apply_fixups(MethodData* mdo,
                         const ProfileCheckpoint::Fixup* fixups,
                         u4 fixup_count,
                         GrowableArray<char*>& symtab,
                         ProfileCheckpoint::LoaderId loader,
                         TRAPS) {
  Handle loader_h;
  switch (loader) {
    case ProfileCheckpoint::LoaderId::BOOT:      loader_h = Handle(); break;
    case ProfileCheckpoint::LoaderId::PLATFORM:  loader_h = Handle(THREAD, SystemDictionary::java_platform_loader()); break;
    case ProfileCheckpoint::LoaderId::APP:       loader_h = Handle(THREAD, SystemDictionary::java_system_loader()); break;
    default:                                     loader_h = Handle(); break;
  }
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
    Symbol* sym = SymbolTable::new_symbol(cname);
    Klass* k = SystemDictionary::resolve_or_fail(sym, loader_h, true, THREAD);
    if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; k = nullptr; }
    if (k != nullptr && k->is_instance_klass()) {
      address cell_addr = (address)mdo + fx.offset_in_mdo;
      intptr_t* cell = (intptr_t*)cell_addr;
      *cell = TypeEntries::with_status(InstanceKlass::cast(k), *cell);
    } else {
      log_debug(compilation)("MDO checkpoint: fixup unresolved %s (loader=%d) at off=%u",
                             cname, (int)loader, fx.offset_in_mdo);
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

static bool write_str(fileStream* out, const char* s) {
  u4 len = (u4)strlen(s);
  if (!write_u4(out, len)) return false;
  return write_exact(out, s, len);
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
  if (!write_u4(out, h.version)) return false;
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
  if (!read_u4(in, h.version)) return false;
  if (h.version != 3u) return false;
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
  h.version = 3u;
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

bool ProfileCheckpoint::Record::write(fileStream* out, const Record& r, const void* mdo_bytes, const Fixup* fixups, const void* mc_bytes) {
  if (!write_u4(out, r.key.klass.id)) return false;
  if (!write_u4(out, r.key.name.id))  return false;
  if (!write_u4(out, r.key.sig.id))   return false;
  u1 loader = (u1)r.key.loader;
  if (!write_exact(out, &loader, sizeof(loader))) return false;
  if (!write_u4(out, r.mdo_size)) return false;
  if (!write_u4(out, r.fixup_count)) return false;
  for (u4 i = 0; i < r.fixup_count; i++) {
    if (!write_u4(out, fixups[i].offset_in_mdo)) return false;
    u1 kind = (u1)fixups[i].kind;
    if (!write_exact(out, &kind, sizeof(kind))) return false;
    if (!write_u4(out, fixups[i].target.id)) return false;
  }
  if (!write_exact(out, mdo_bytes, r.mdo_size)) return false;
  if (!write_u4(out, r.mc_size)) return false;
  if (r.mc_size > 0) {
    if (!write_exact(out, mc_bytes, r.mc_size)) return false;
  }
  return true;
}

bool ProfileCheckpoint::Record::read(FILE* in, Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes) {
  if (!read_u4(in, r.key.klass.id)) return false;
  if (!read_u4(in, r.key.name.id))  return false;
  if (!read_u4(in, r.key.sig.id))   return false;
  u1 loader = 0;
  if (!read_exact(in, &loader, sizeof(loader))) return false;
  r.key.loader = (LoaderId)loader;
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
  if (!read_u4(in, r.mc_size)) return false;
  mc_bytes = nullptr;
  if (r.mc_size > 0) {
    mc_bytes = (char*)os::malloc(r.mc_size, mtInternal);
    if (mc_bytes == nullptr) { if (fixups) os::free(fixups); if (mdo_bytes) os::free(mdo_bytes); return false; }
    if (!read_exact(in, mc_bytes, r.mc_size)) { os::free(mc_bytes); if (fixups) os::free(fixups); if (mdo_bytes) os::free(mdo_bytes); return false; }
  }
  return true;
}

// --- Restore support (minimal v1): resolve by system loader, link, alloc MDO, memcpy, sanitize ---

static InstanceKlass* resolve_klass_utf8(const char* name, TRAPS) {
  Symbol* sym = SymbolTable::new_symbol(name);
  oop sys_loader_oop = SystemDictionary::java_system_loader();
  Handle loader(THREAD, sys_loader_oop);
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

void ProfileCheckpoint::load(JavaThread* THREAD) {
  if (!LoadMDOAtStartup || MDOReplayLoadFile == nullptr) return;
  FILE* f = os::fopen(MDOReplayLoadFile, "rb");
  if (f == nullptr) { return; }
  ResourceMark rm;
  log_info(compilation)("MDO checkpoint: loading (binary) from %s", MDOReplayLoadFile);

  ProfileCheckpoint::Header hdr;
  if (!ProfileCheckpoint::Header::read(f, hdr)) { fclose(f); return; }
  u4 sym_count = hdr.sym_count;
  u4 rec_total = hdr.rec_count;
  // Read symtab
  GrowableArray<char*> symtab((int)sym_count);
  for (u4 si = 0; si < sym_count; si++) {
    char* s = read_str(f);
    if (s == nullptr) { fclose(f); return; }
    symtab.append(s);
  }
  int records_read = 0;
  int records_installed = 0;
  int size_mismatch = 0;

  for (u4 i = 0; i < rec_total; i++) {
    ProfileCheckpoint::Record rec;
    ProfileCheckpoint::Fixup* fixups = nullptr;
    char* mdo_bytes = nullptr;
    char* mc_bytes = nullptr;
    if (!ProfileCheckpoint::Record::read(f, rec, fixups, mdo_bytes, mc_bytes)) { log_debug(compilation)("MDO checkpoint: record read failed at %u", i); break; }
    const char* kname = symtab.at((int)rec.key.klass.id);
    const char* mname = symtab.at((int)rec.key.name.id);
    const char* msig  = symtab.at((int)rec.key.sig.id);
    records_read++;
    if (rec.mdo_size == 0) { log_debug(compilation)("MDO checkpoint: empty MDO payload for %s %s %s", kname, mname, msig); if (fixups) os::free(fixups); if (mdo_bytes) os::free(mdo_bytes); continue; }

    InstanceKlass* holder = resolve_klass_utf8(kname, THREAD);
    if (holder != nullptr) {
      Method* target = resolve_method_utf8(holder, mname, msig);
      if (target != nullptr) {
        holder->link_class(THREAD);
        if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }
        if (target->method_data() == nullptr) {
          methodHandle mh(THREAD, target);
          target->build_profiling_method_data(mh, CHECK);
          if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; }
        }
        MethodData* mdo = target->method_data();
        if (mdo != nullptr) {
          if (copy_mdo_payload(mdo, mdo_bytes, rec.mdo_size)) {
            sanitize_type_entries(mdo);
            if (fixups != nullptr && rec.fixup_count > 0) {
              apply_fixups(mdo, fixups, rec.fixup_count, symtab, rec.key.loader, THREAD);
            }

            records_installed++;
            // Restore MethodCounters snapshot if present and counters object exists
            if (rec.mc_size > 0) {
              MethodCounters* mc = target->method_counters();
              if (mc != nullptr) {
                const size_t ic_sz = sizeof(InvocationCounter);
                if (rec.mc_size >= ic_sz * 2 + sizeof(jlong) + sizeof(float) + sizeof(jint) + 2 * sizeof(u1)) {
                  char* p = mc_bytes;
                  // invocation counter
                  Copy::conjoint_jbytes(p, (char*)mc->invocation_counter(), (jlong)ic_sz); p += ic_sz;
                  // backedge counter
                  Copy::conjoint_jbytes(p, (char*)mc->backedge_counter(), (jlong)ic_sz); p += ic_sz;
                  // prev_time
                  jlong prev_time = *(jlong*)p; p += sizeof(jlong);
                  mc->set_prev_time(prev_time);
                  // rate
                  float rate = *(float*)p; p += sizeof(float);
                  mc->set_rate(rate);
                  // prev_event_count
                  jint pec = *(jint*)p; p += sizeof(jint);
                  mc->set_prev_event_count(pec);
                  // highest levels
                  int hc = (int)(u1)(*p++);
                  int hosr = (int)(u1)(*p++);
                  mc->set_highest_comp_level(hc);
                  mc->set_highest_osr_comp_level(hosr);
                }
              }
            }
            if (PrintMDOAfterLoad) {
              tty->print_cr("[AfterLoad] %s %s %s", kname, mname, msig);
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
          } else {
            log_debug(compilation)("MDO checkpoint: copy payload failed for %s %s %s (size=%u)", kname, mname, msig, rec.mdo_size);
            size_mismatch++;
          }
        } else {
          log_debug(compilation)("MDO checkpoint: MethodData allocation/build failed for %s %s %s", kname, mname, msig);
        }
      } else {
        log_debug(compilation)("MDO checkpoint: resolve method failed for %s %s %s", kname, mname, msig);
      }
    } else {
      log_debug(compilation)("MDO checkpoint: resolve class failed for %s", kname);
    }
    if (fixups != nullptr) os::free(fixups);
    if (mdo_bytes != nullptr) os::free(mdo_bytes);
    if (mc_bytes != nullptr) os::free(mc_bytes);
  }
  fclose(f);
  log_info(compilation)("MDO checkpoint: loaded %d records (%d installed, %d size mismatch)",
                        records_read, records_installed, size_mismatch);
}

void ProfileCheckpoint::dump_to_stream(fileStream* out) {
  ResourceMark rm;
  GrowableArray<Method*> methods(1024);
  // We can't pass lambdas directly; reuse pattern from old dumper
  static GrowableArray<Method*>* g_methods;
  g_methods = &methods;
  auto collect_with_mdo = [](Method* m) {
    if (m != nullptr && m->method_data() != nullptr) {
      g_methods->push(m);
    }
  };
  SystemDictionary::methods_do(collect_with_mdo);

  // Symtab builder utilities
  GrowableArray<const char*> symtab(256);
  auto add_unique = [&](const char* s){
    for (int i = 0; i < symtab.length(); i++) {
      if (strcmp(symtab.at(i), s) == 0) return;
    }
    symtab.append(s);
  };
  auto lookup_id = [&](const char* s)->u4 {
    for (int i = 0; i < symtab.length(); i++) {
      if (strcmp(symtab.at(i), s) == 0) return (u4)i;
    }
    // Should not happen once symtab is frozen
    assert(false, "Symbol not found in symtab");
    return (u4)UINT_MAX;
  };

  struct RecNames { const char* kname; const char* mname; const char* sig; u4 mdo_size; const void* mdo_ptr; };
  GrowableArray<RecNames> recs(1024);

  for (int i = 0; i < methods.length(); i++) {
    Method* m = methods.at(i);
    MethodData* mdo = m->method_data();
    if (mdo == nullptr) continue;
    MutexLocker ml(mdo->extra_data_lock(), Mutex::_no_safepoint_check_flag);
    InstanceKlass* holder = m->method_holder();
    const char* kname = holder->name()->as_utf8();
    const char* mname = m->name()->as_utf8();
    const char* sig   = m->signature()->as_utf8();
    RecNames r;
    r.kname = kname;
    r.mname = mname;
    r.sig   = sig;
    r.mdo_size = (u4)mdo->size_in_bytes();
    r.mdo_ptr  = (const void*)mdo;
    recs.append(r);
  }

  // Pre-scan all methods to collect fixups as raw strings
  GrowableArray< GrowableArray<FixupText>* > fixups_per_rec(recs.length());
  for (int ri = 0; ri < recs.length(); ri++) {
    Method* m = methods.at(ri);
    MethodData* mdo = m->method_data();
    GrowableArray<FixupText>* fx = new GrowableArray<FixupText>(16);
    collect_type_fixups_text(mdo, *fx);
    fixups_per_rec.append(fx);
  }

  // Build/freeze symtab from all names: method keys + fixup names
  for (int ri = 0; ri < recs.length(); ri++) {
    add_unique(recs.at(ri).kname);
    add_unique(recs.at(ri).mname);
    add_unique(recs.at(ri).sig);
    GrowableArray<FixupText>* fx = fixups_per_rec.at(ri);
    for (int i = 0; i < fx->length(); i++) add_unique(fx->at(i).name);
  }

  // Now write finalized header and symtab
  ProfileCheckpoint::Writer writer(out);
  writer.write_header((u4)symtab.length(), (u4)recs.length());

  for (int si = 0; si < symtab.length(); si++) {
    const char* s = symtab.at(si);
    u4 len = (u4)strlen(s);
    write_u4(out, len);
    write_exact(out, s, len);
  }

  // Write records using pre-built fixups
  u4 emitted = 0;
  for (int ri = 0; ri < recs.length(); ri++) {
    const RecNames& rn = recs.at(ri);
    Method* m = methods.at(ri);
    MethodData* mdo = m->method_data();
    ProfileCheckpoint::Record rec;
    oop cl = m->method_holder()->class_loader();
    if (cl == nullptr) {
      rec.key.loader = LoaderId::BOOT;
    } else if (SystemDictionary::is_platform_class_loader(cl)) {
      rec.key.loader = LoaderId::PLATFORM;
    } else {
      rec.key.loader = LoaderId::APP;
    }
    rec.key.klass.id = lookup_id(rn.kname);
    rec.key.name.id  = lookup_id(rn.mname);
    rec.key.sig.id   = lookup_id(rn.sig);
    rec.key.bytecode_crc32 = 0;
    rec.mdo_size = rn.mdo_size;
    GrowableArray<FixupText>* fx_text = fixups_per_rec.at(ri);
    GrowableArray<Fixup> fx_ids(fx_text->length());
    for (int i = 0; i < fx_text->length(); i++) {
      Fixup fxi; fxi.offset_in_mdo = fx_text->at(i).offset_in_mdo; fxi.kind = fx_text->at(i).kind; fxi.target.id = lookup_id(fx_text->at(i).name); fx_ids.append(fxi);
    }
    rec.fixup_count = (u4)fx_ids.length();
    // Build MethodCounters snapshot (optional)
    const void* mc_bytes = nullptr;
    GrowableArray<char> mc_buf(0);
    MethodCounters* mc = m->method_counters();
    if (mc != nullptr) {
      const size_t ic_sz = sizeof(InvocationCounter);
      const size_t mc_sz = ic_sz * 2 + sizeof(jlong) + sizeof(float) + sizeof(jint) + 2 * sizeof(u1);
      for (size_t fill = 0; fill < mc_sz; fill++) mc_buf.append((char)0);
      char* p = mc_buf.adr_at(0);
      // invocation counter
      Copy::conjoint_jbytes((char*)mc->invocation_counter(), p, (jlong)ic_sz);
      p += ic_sz;
      // backedge counter
      Copy::conjoint_jbytes((char*)mc->backedge_counter(), p, (jlong)ic_sz);
      p += ic_sz;
      // prev_time
      *(jlong*)p = mc->prev_time(); p += sizeof(jlong);
      // rate
      *(float*)p = mc->rate(); p += sizeof(float);
      // prev_event_count
      *(jint*)p = mc->prev_event_count(); p += sizeof(jint);
      // highest levels
      *p++ = (u1)mc->highest_comp_level();
      *p++ = (u1)mc->highest_osr_comp_level();
      rec.mc_size = (u4)mc_sz;
      mc_bytes = mc_buf.adr_at(0);
    } else {
      rec.mc_size = 0;
    }
    ProfileCheckpoint::Record::write(out, rec, rn.mdo_ptr, rec.fixup_count ? fx_ids.adr_at(0) : nullptr, mc_bytes);
    if (PrintMDOAtDump) {
      const char* kname = rn.kname;
      const char* mname = rn.mname;
      const char* sig   = rn.sig;
      tty->print_cr("[Dump] %s %s %s", kname, mname, sig);
      tty->print_cr("[MethodData]");
      mdo->print_data_on(tty);
      tty->print_cr("[MethodCounters]");
      MethodCounters* mc = m->method_counters();
      if (mc != nullptr) {
        mc->print_data_on(tty);
      } else {
        tty->print_cr("  (none)");
      }
    }
    emitted++;
  }
  log_info(compilation)("MDO checkpoint: dumped %u MDOs (sym=%d)", emitted, symtab.length());
}


