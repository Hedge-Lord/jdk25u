#include "classfile/systemDictionary.hpp"
#include "classfile/symbolTable.hpp"
#include "oops/instanceKlass.hpp"
#include "oops/method.hpp"
#include "oops/methodData.hpp"
#include "runtime/javaThread.hpp"
#include "runtime/handles.inline.hpp"
#include "runtime/os.hpp"
#include "services/mdoReplayLoad.hpp"
#include "logging/log.hpp"
#include "services/mdoReplay_globals.hpp"
#include "utilities/ostream.hpp"
#include "utilities/copy.hpp"
#include "memory/metaspace.hpp"

// Very simple text parser matching the dump format in mdoReplayDump.cpp.
// Grammar (one line per MDO):
// MethodData <klass> <name> <signature> <state> <invocation_counter> orig <len> <bytes...> data <N> <words...> oops <K> (<off> <klass>)... methods <M> (<off> <klass> <name> <sig>)...

static char* read_word(FILE* f, char* buf, int buflen) {
  int c;
  do { c = fgetc(f); if (c == EOF) return nullptr; } while (c == ' ' || c == '\t' || c == '\n' || c == '\r');
  int i = 0; buf[i++] = (char)c;
  while (i < buflen - 1) { c = fgetc(f); if (c == EOF || c == ' ' || c == '\t' || c == '\n' || c == '\r') break; buf[i++] = (char)c; }
  buf[i] = '\0';
  return buf;
}

static bool read_int(FILE* f, int& out) {
  char tmp[64]; if (read_word(f, tmp, sizeof(tmp)) == nullptr) return false; out = atoi(tmp); return true;
}

static bool read_hex_word(FILE* f, uintptr_t& out) {
  char tmp[64]; if (read_word(f, tmp, sizeof(tmp)) == nullptr) return false; out = (uintptr_t)strtoull(tmp, nullptr, 16); return true;
}

static InstanceKlass* resolve_klass(const char* qname, TRAPS) {
  // qname is quoted ascii; strip quotes if present
  const char* s = qname;
  size_t len = strlen(s);
  if (len >= 2 && s[0] == '"' && s[len-1] == '"') { s++; len -= 2; }
  Symbol* sym = SymbolTable::new_symbol(s, (int)len);
  // Use the Java system loader (same as ciReplay) instead of bootstrap-only
  oop sys_loader_oop = SystemDictionary::java_system_loader();
  if (log_is_enabled(Debug, compilation)) {
    log_debug(compilation)("MDO replay: resolve_klass name=%s system_loader=%p", s, (void*)sys_loader_oop);
  }
  Handle loader(THREAD, sys_loader_oop);
  Klass* k = SystemDictionary::resolve_or_fail(sym, loader, true, THREAD);
  if (HAS_PENDING_EXCEPTION) {
    if (log_is_enabled(Debug, compilation)) {
      log_debug(compilation)("MDO replay: resolve_klass failed for %s (exception), clearing and skipping", s);
    }
    CLEAR_PENDING_EXCEPTION;
    return nullptr;
  }
  if (log_is_enabled(Debug, compilation)) {
    log_debug(compilation)("MDO replay: resolve_klass %s -> %p", s, (void*)k);
  }
  if (k != nullptr && k->is_instance_klass()) return InstanceKlass::cast(k);
  return nullptr;
}

static Method* resolve_method(InstanceKlass* ik, const char* mname_q, const char* sig_q) {
  const char* mn = mname_q; size_t ln = strlen(mn); if (ln >= 2 && mn[0]=='"' && mn[ln-1]=='"') { mn++; ln-=2; }
  const char* sg = sig_q;  size_t ls = strlen(sg); if (ls >= 2 && sg[0]=='"' && sg[ls-1]=='"') { sg++; ls-=2; }
  return ik->find_method(SymbolTable::new_symbol(mn, (int)ln), SymbolTable::new_symbol(sg, (int)ls));
}

// ---------------- Parsing helpers ----------------
static bool parse_header(FILE* f,
                         char* kname, size_t kcap,
                         char* mname, size_t mncap,
                         char* msig, size_t mscap,
                         int& state_out, int& invc_out, int& backc_out) {
  char tmp[4096];
  char* kw = read_word(f, tmp, sizeof(tmp)); if (kw == nullptr) return false; strncpy(kname, kw, kcap);
  char* mw = read_word(f, tmp, sizeof(tmp)); if (mw == nullptr) return false; strncpy(mname, mw, mncap);
  char* sw = read_word(f, tmp, sizeof(tmp)); if (sw == nullptr) return false; strncpy(msig, sw, mscap);
  if (!read_int(f, state_out)) return false;
  if (!read_int(f, invc_out)) return false;
  if (!read_int(f, backc_out)) return false;
  return true;
}

static bool parse_orig(FILE* f, GrowableArray<unsigned char>& out_bytes) {
  char tag[32]; if (read_word(f, tag, sizeof(tag)) == nullptr || strcmp(tag, "orig") != 0) return false;
  int orig_len = 0; if (!read_int(f, orig_len)) return false;
  for (int i = 0; i < orig_len; i++) {
    int b = 0; if (!read_int(f, b)) return false; out_bytes.push((unsigned char)(b & 0xFF));
  }
  return true;
}

static bool parse_data_words(FILE* f, GrowableArray<uintptr_t>& words) {
  char tag[32]; if (read_word(f, tag, sizeof(tag)) == nullptr || strcmp(tag, "data") != 0) return false;
  int nwords = 0; if (!read_int(f, nwords)) return false;
  for (int i = 0; i < nwords; i++) { uintptr_t w = 0; if (!read_hex_word(f, w)) return false; words.push(w); }
  return true;
}

static bool parse_oops(FILE* f,
                       GrowableArray<int>& class_offs,
                       GrowableArray<InstanceKlass*>& class_vals,
                       JavaThread* THREAD) {
  char tag[32]; if (read_word(f, tag, sizeof(tag)) == nullptr || strcmp(tag, "oops") != 0) return false;
  int nclasses = 0; if (!read_int(f, nclasses)) return false;
  for (int i = 0; i < nclasses; i++) {
    int off = 0; if (!read_int(f, off)) return false;
    char cname[4096]; if (read_word(f, cname, sizeof(cname)) == nullptr) return false;
    InstanceKlass* ck = resolve_klass(cname, THREAD);
    class_offs.push(off);
    class_vals.push(ck);
  }
  return true;
}

static bool parse_methods(FILE* f,
                          GrowableArray<int>& method_offs,
                          GrowableArray<Method*>& method_vals,
                          JavaThread* THREAD) {
  char tag[32]; if (read_word(f, tag, sizeof(tag)) == nullptr || strcmp(tag, "methods") != 0) return false;
  int nmethods = 0; if (!read_int(f, nmethods)) return false;
  for (int i = 0; i < nmethods; i++) {
    int off = 0; if (!read_int(f, off)) return false;
    char mkname[4096], mmname[4096], mmsig[4096];
    if (read_word(f, mkname, sizeof(mkname)) == nullptr) return false;
    if (read_word(f, mmname, sizeof(mmname)) == nullptr) return false;
    if (read_word(f, mmsig, sizeof(mmsig)) == nullptr) return false;
    InstanceKlass* mik = resolve_klass(mkname, THREAD);
    Method* mm = (mik == nullptr) ? nullptr : resolve_method(mik, mmname, mmsig);
    method_offs.push(off);
    method_vals.push(mm);
  }
  return true;
}

// Load a single MethodData record; return false only on parse failure (break), true otherwise
static bool load_one_mdo(FILE* f,
                         JavaThread* THREAD,
                         int& size_mismatch,
                         int& records_installed) {
  char kname[4096], mname[4096], msig[4096]; int state = 0, invc = 0, backc = 0;
  if (!parse_header(f, kname, sizeof(kname), mname, sizeof(mname), msig, sizeof(msig), state, invc, backc)) return false;
  GrowableArray<unsigned char> orig_bytes(64);
  if (!parse_orig(f, orig_bytes)) return false;
  GrowableArray<uintptr_t> words(16);
  if (!parse_data_words(f, words)) return false;
  GrowableArray<int> class_offs(8);
  GrowableArray<InstanceKlass*> class_vals(8);
  if (!parse_oops(f, class_offs, class_vals, THREAD)) return false;
  GrowableArray<int> method_offs(4);
  GrowableArray<Method*> method_vals(4);
  if (!parse_methods(f, method_offs, method_vals, THREAD)) return false;

  // Resolve target Method and ensure MDO exists
  InstanceKlass* holder = resolve_klass(kname, THREAD);
  if (holder == nullptr) return true;
  Method* target = resolve_method(holder, mname, msig);
  if (target == nullptr) return true;
  // Ensure the holder is linked before creating or touching profiling data
  holder->link_class(THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; return true; }
  if (target->method_data() == nullptr) {
    methodHandle mh(THREAD, target);
    target->build_profiling_method_data(mh, CHECK_(true));
    if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; return true; }
  }
  MethodData* mdo = target->method_data();
  if (mdo == nullptr) return true;

  // Reset escape analysis info to avoid inconsistent state
  mdo->clear_escape_info();

  // Restore invocation/backedge counters into MethodData and MethodCounters
  {
    // Set MDO counters (InvocationCounter objects) via atomic helpers
    mdo->invocation_counter()->set((unsigned)invc);
    mdo->backedge_counter()->set((unsigned)backc);
  }

  // Restore CompilerCounters header bytes ("orig")
  if (orig_bytes.length() > 0) {
    size_t cc_offset = in_bytes(MethodData::trap_history_offset()) - in_bytes(MethodData::CompilerCounters::trap_history_offset());
    unsigned char* dst = (unsigned char*)((address)mdo + cc_offset);
    size_t copy_len = orig_bytes.length();
    if (copy_len > sizeof(MethodData::CompilerCounters)) copy_len = sizeof(MethodData::CompilerCounters);
    // Copy bytes back into the MDO's CompilerCounters
    Copy::conjoint_jbytes((const char*)orig_bytes.adr_at(0), (char*)dst, (jlong)copy_len);
  }

  // Size check: must match
  int total_cells = (mdo->data_size() + mdo->extra_data_size()) / (int)sizeof(intptr_t);
  if ((int)words.length() != total_cells) { size_mismatch++; return true; }

  // Copy full cells (data + extra)
  {
#ifdef _LP64
    Copy::conjoint_jlongs_atomic((jlong*)words.adr_at(0), (jlong*)mdo->data_base(), words.length());
#else
    Copy::conjoint_jints_atomic((jint*)words.adr_at(0), (jint*)mdo->data_base(), words.length());
#endif
  }

  // Zero-out the extra-data trap/arg-info slice and synthesize minimal ArgInfoData
  {
    DataLayout* extra_base = mdo->extra_data_base();
    DataLayout* args_limit = mdo->args_data_limit();
    if (args_limit > extra_base) {
      size_t bytes = ((address)args_limit) - ((address)extra_base);
      memset((void*)extra_base, 0, bytes);
    }
    int nparams = target->size_of_parameters();
    if (nparams > 0) {
      const int cell_size = (int)sizeof(intptr_t);
      const int header_bytes = DataLayout::header_size_in_bytes();
      const size_t total_bytes = (size_t)header_bytes + (size_t)(nparams + 1) * (size_t)cell_size;
      if (((address)args_limit) >= ((address)extra_base) + total_bytes) {
        address arg_info_start = ((address)args_limit) - total_bytes;
        memset((void*)arg_info_start, 0, total_bytes);
        DataLayout* aid = (DataLayout*)arg_info_start;
        aid->set_header(0);
        *(u1*)((address)aid + in_bytes(DataLayout::tag_offset())) = (u1)DataLayout::arg_info_data_tag;
        aid->set_cell_at(0, (intptr_t)nparams);
      }
    }
  }

  // Sanitize: clear all type-entry Klass* pointers to avoid stale addresses; preserve status bits
  {
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
          for (int i = 0; i < ctd->number_of_arguments(); i++) {
            int off_b = in_bytes(ctd->argument_type_offset(i));
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
          for (int i = 0; i < vctd->number_of_arguments(); i++) {
            int off_b = in_bytes(vctd->argument_type_offset(i));
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
    ParametersTypeData* p = mdo->parameters_type_data();
    if (p != nullptr) {
      address p_dp = p->dp();
      for (int i = 0; i < p->number_of_parameters(); i++) {
        int off_b = in_bytes(ParametersTypeData::type_offset(i));
        intptr_t* cell = (intptr_t*)(p_dp + off_b);
        *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
      }
    }
  }

  // Patch method pointers in extra data (if any): may be nullptr
  int patched_methods = 0;
  for (int i = 0; i < method_offs.length(); i++) {
    int off = method_offs.at(i);
    intptr_t* slot = ((intptr_t*)mdo->data_base()) + off;
    Method* mv = method_vals.at(i);
    *(Method**)slot = mv;
    patched_methods++;
  }

  // Final scrub: ensure all Klass* in type entries are live; null out otherwise
  {
    for (ProfileData* pd = mdo->first_data(); mdo->is_valid(pd); pd = mdo->next_data(pd)) {
      if (pd->is_VirtualCallData() || pd->is_ReceiverTypeData()) {
        ReceiverTypeData* rtd = pd->as_ReceiverTypeData();
        for (uint row = 0; row < rtd->row_limit(); row++) {
          int off_b = in_bytes(ReceiverTypeData::receiver_offset(row));
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          Klass* k = (Klass*)TypeEntries::klass_part(*cell);
          if (k != nullptr && !Metaspace::contains((address)k)) {
            *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
          }
        }
      }
      if (pd->is_CallTypeData()) {
        CallTypeData* ctd = (CallTypeData*)pd;
        if (ctd->has_arguments()) {
          for (int i = 0; i < ctd->number_of_arguments(); i++) {
            int off_b = in_bytes(ctd->argument_type_offset(i));
            intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
            Klass* k = (Klass*)TypeEntries::klass_part(*cell);
            if (k != nullptr && !Metaspace::contains((address)k)) {
              *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
            }
          }
        }
        if (ctd->has_return()) {
          int off_b = in_bytes(ctd->return_type_offset());
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          Klass* k = (Klass*)TypeEntries::klass_part(*cell);
          if (k != nullptr && !Metaspace::contains((address)k)) {
            *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
          }
        }
      }
      if (pd->is_VirtualCallTypeData()) {
        VirtualCallTypeData* vctd = pd->as_VirtualCallTypeData();
        if (vctd->has_arguments()) {
          for (int i = 0; i < vctd->number_of_arguments(); i++) {
            int off_b = in_bytes(vctd->argument_type_offset(i));
            intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
            Klass* k = (Klass*)TypeEntries::klass_part(*cell);
            if (k != nullptr && !Metaspace::contains((address)k)) {
              *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
            }
          }
        }
        if (vctd->has_return()) {
          int off_b = in_bytes(vctd->return_type_offset());
          intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
          Klass* k = (Klass*)TypeEntries::klass_part(*cell);
          if (k != nullptr && !Metaspace::contains((address)k)) {
            *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
          }
        }
      }
    }
    ParametersTypeData* p2 = mdo->parameters_type_data();
    if (p2 != nullptr) {
      address p_dp = p2->dp();
      for (int i = 0; i < p2->number_of_parameters(); i++) {
        int off_b = in_bytes(ParametersTypeData::type_offset(i));
        intptr_t* cell = (intptr_t*)(p_dp + off_b);
        Klass* k = (Klass*)TypeEntries::klass_part(*cell);
        if (k != nullptr && !Metaspace::contains((address)k)) {
          *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
        }
      }
    }
  }

  records_installed++;
  if (log_is_enabled(Debug, compilation)) {
    log_debug(compilation)("MDO replay: installed %s %s %s (cells=%d, oops=%d, methods=%d)",
                           kname, mname, msig, (int)words.length(), 0, patched_methods);
  }
  return true;
}

void MDOReplayLoad::load(JavaThread* THREAD) {
  if (!LoadMDOAtStartup || MDOReplayLoadFile == nullptr) return;
  FILE* f = os::fopen(MDOReplayLoadFile, "r");
  if (f == nullptr) { return; }
  ResourceMark rm;
  log_info(compilation)("MDO replay: loading from %s", MDOReplayLoadFile);
  if (log_is_enabled(Debug, compilation)) {
    log_debug(compilation)("MDO replay: system_loader at load entry: %p", (void*)SystemDictionary::java_system_loader());
  }
  int records_read = 0;
  int records_installed = 0;
  int size_mismatch = 0;
  char word[4096];
  while (read_word(f, word, sizeof(word)) != nullptr) {
    if (strcmp(word, "#") == 0) { // comment line: skip to EOL
      int c; while ((c = fgetc(f)) != EOF && c != '\n') {}
      continue;
    }
    if (strcmp(word, "MethodData") != 0) {
      // skip line
      int c; while ((c = fgetc(f)) != EOF && c != '\n') {}
      continue;
    }
    records_read++;
    if (!load_one_mdo(f, THREAD, size_mismatch, records_installed)) break;
  }
  fclose(f);
  log_info(compilation)("MDO replay: loaded %d records (%d installed, %d size mismatch)",
                        records_read, records_installed, size_mismatch);
}


