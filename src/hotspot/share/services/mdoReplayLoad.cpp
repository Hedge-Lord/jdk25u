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
  Handle loader(THREAD, SystemDictionary::java_system_loader());
  Klass* k = SystemDictionary::resolve_or_fail(sym, loader, true, THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; return nullptr; }
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
                         int& state_out, int& invc_out) {
  char tmp[4096];
  char* kw = read_word(f, tmp, sizeof(tmp)); if (kw == nullptr) return false; strncpy(kname, kw, kcap);
  char* mw = read_word(f, tmp, sizeof(tmp)); if (mw == nullptr) return false; strncpy(mname, mw, mncap);
  char* sw = read_word(f, tmp, sizeof(tmp)); if (sw == nullptr) return false; strncpy(msig, sw, mscap);
  if (!read_int(f, state_out)) return false;
  if (!read_int(f, invc_out)) return false;
  return true;
}

static bool parse_orig(FILE* f) {
  char tag[32]; if (read_word(f, tag, sizeof(tag)) == nullptr || strcmp(tag, "orig") != 0) return false;
  int orig_len = 0; if (!read_int(f, orig_len)) return false;
  for (int i = 0; i < orig_len; i++) { int b = 0; if (!read_int(f, b)) return false; }
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

void MDOReplayLoad::load(JavaThread* THREAD) {
  if (!LoadMDOAtStartup || MDOReplayLoadFile == nullptr) return;
  FILE* f = os::fopen(MDOReplayLoadFile, "r");
  if (f == nullptr) { return; }
  ResourceMark rm;
  log_info(compilation)("MDO replay: loading from %s", MDOReplayLoadFile);
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
    char kname[4096], mname[4096], msig[4096]; int state = 0, invc = 0;
    if (!parse_header(f, kname, sizeof(kname), mname, sizeof(mname), msig, sizeof(msig), state, invc)) break;
    if (!parse_orig(f)) break;
    GrowableArray<uintptr_t> words(16);
    if (!parse_data_words(f, words)) break;
    GrowableArray<int> class_offs(8);
    GrowableArray<InstanceKlass*> class_vals(8);
    if (!parse_oops(f, class_offs, class_vals, THREAD)) break;
    GrowableArray<int> method_offs(4);
    GrowableArray<Method*> method_vals(4);
    if (!parse_methods(f, method_offs, method_vals, THREAD)) break;

    // Resolve target Method and ensure MDO exists
    InstanceKlass* holder = resolve_klass(kname, THREAD);
    if (holder == nullptr) continue;
    Method* target = resolve_method(holder, mname, msig);
    if (target == nullptr) continue;
  // Ensure the holder is linked before creating or touching profiling data
  holder->link_class(THREAD);
  if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; continue; }
    if (target->method_data() == nullptr) {
      methodHandle mh(THREAD, target);
      target->build_profiling_method_data(mh, CHECK);
      if (HAS_PENDING_EXCEPTION) { CLEAR_PENDING_EXCEPTION; continue; }
    }
    MethodData* mdo = target->method_data();
    if (mdo == nullptr) continue;

    // Reset escape analysis info to avoid inconsistent state
    mdo->clear_escape_info();

    // Size check: must match
    int total_cells = (mdo->data_size() + mdo->extra_data_size()) / (int)sizeof(intptr_t);
    if ((int)words.length() != total_cells) { size_mismatch++; continue; }

  // Copy only up to args_data_limit: primary data + extra_data + params header region
  // We will zero the trap/arg-info extra slice immediately after.
  {
#ifdef _LP64
    Copy::conjoint_jlongs_atomic((jlong*)words.adr_at(0), (jlong*)mdo->data_base(), words.length());
#else
    Copy::conjoint_jints_atomic((jint*)words.adr_at(0), (jint*)mdo->data_base(), words.length());
#endif
  }

  // Zero-out the extra-data trap/arg-info slice to avoid inconsistent tags
  {
    DataLayout* extra_base = mdo->extra_data_base();
    DataLayout* args_limit = mdo->args_data_limit();
    if (args_limit > extra_base) {
      size_t bytes = ((address)args_limit) - ((address)extra_base);
      memset((void*)extra_base, 0, bytes);
    }

    // Synthesize a minimal ArgInfoData at the end with all zeros so CI can update
    // Find the start of ArgInfoData record: it is the last entry before args_data_limit
    // We place a header right before args_data_limit with tag=arg_info_data_tag and array_len=method parameter count
    int nparams = target->size_of_parameters();
    if (nparams > 0) {
      // ArgInfoData occupies header + (len cell + nparams entries) cells
      const int cell_size = (int)sizeof(intptr_t);
      const int header_bytes = DataLayout::header_size_in_bytes();
      const size_t total_bytes = (size_t)header_bytes + (size_t)(nparams + 1) * (size_t)cell_size;
      if (((address)args_limit) >= ((address)extra_base) + total_bytes) {
        address arg_info_start = ((address)args_limit) - total_bytes;
        // Zero region and place header
        memset((void*)arg_info_start, 0, total_bytes);
        DataLayout* aid = (DataLayout*)arg_info_start;
        aid->set_header(0);
        *(u1*)((address)aid + in_bytes(DataLayout::tag_offset())) = (u1)DataLayout::arg_info_data_tag;
        // Set array length in first cell
        aid->set_cell_at(0, (intptr_t)nparams);
      }
    }
  }

    // Sanitize: clear all type-entry Klass* pointers to avoid stale addresses;
    // we'll re-patch known ones below. Preserve status bits.
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

    // Patch class pointers (TypeEntries): null on failure, preserving status bits
    int patched_classes = 0;
    // Safety-first: skip repatching TypeEntries Klass* to avoid stale metadata crashes.
    // Profiles still contribute counters without receiver types.

    // Patch method pointers in extra data: null on failure
    int patched_methods = 0;
    for (int i = 0; i < method_offs.length(); i++) {
      int off = method_offs.at(i);
      intptr_t* slot = ((intptr_t*)mdo->data_base()) + off;
      Method* mv = method_vals.at(i);
      *(Method**)slot = mv; // may be nullptr
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
            if (k != nullptr) {
              if (!Metaspace::contains((address)k)) {
                *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
              }
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
              if (k != nullptr) {
                if (!Metaspace::contains((address)k)) {
                  *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
                }
              }
            }
          }
          if (ctd->has_return()) {
            int off_b = in_bytes(ctd->return_type_offset());
            intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
            Klass* k = (Klass*)TypeEntries::klass_part(*cell);
            if (k != nullptr) {
              if (!Metaspace::contains((address)k)) {
                *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
              }
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
              if (k != nullptr) {
                if (!Metaspace::contains((address)k)) {
                  *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
                }
              }
            }
          }
          if (vctd->has_return()) {
            int off_b = in_bytes(vctd->return_type_offset());
            intptr_t* cell = (intptr_t*)(pd->dp() + off_b);
            Klass* k = (Klass*)TypeEntries::klass_part(*cell);
            if (k != nullptr) {
              if (!Metaspace::contains((address)k)) {
                *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
              }
            }
          }
        }
      }
      ParametersTypeData* p = mdo->parameters_type_data();
      if (p != nullptr) {
        address p_dp = p->dp();
        for (int i = 0; i < p->number_of_parameters(); i++) {
          int off_b = in_bytes(ParametersTypeData::type_offset(i));
          intptr_t* cell = (intptr_t*)(p_dp + off_b);
          Klass* k = (Klass*)TypeEntries::klass_part(*cell);
          if (k != nullptr) {
            if (!Metaspace::contains((address)k)) {
              *cell = TypeEntries::with_status((Klass*)nullptr, *cell);
            }
          }
        }
      }
    }
    records_installed++;
    if (log_is_enabled(Debug, compilation)) {
      log_debug(compilation)("MDO replay: installed %s %s %s (cells=%d, oops=%d, methods=%d)",
                             kname, mname, msig, (int)words.length(), patched_classes, patched_methods);
    }
  }
  fclose(f);
  log_info(compilation)("MDO replay: loaded %d records (%d installed, %d size mismatch)",
                        records_read, records_installed, size_mismatch);
}


