#include "classfile/systemDictionary.hpp"
#include "services/mdoReplay_globals.hpp"
#include "oops/methodData.hpp"
#include "oops/method.hpp"
#include "services/mdoReplayDump.hpp"
#include "utilities/ostream.hpp"
#include "utilities/copy.hpp"
#include "logging/log.hpp"

// Local collector shared with java.cpp style
static GrowableArray<Method*>* g_methods;
static void collect_with_mdo(Method* m) {
  if (m != nullptr && m->method_data() != nullptr) {
    g_methods->push(m);
  }
}

static void dump_header(fileStream* out, Method* m, MethodData* mdo) {
  // Header: MethodData <klass> <name> <signature> <state> <invocation_counter>
  InstanceKlass* holder = m->method_holder();
  const char* kname = holder->name()->as_quoted_ascii();
  const char* mname = m->name()->as_quoted_ascii();
  const char* sig   = m->signature()->as_quoted_ascii();
  const int state = mdo->is_mature() ? 2 /*mature*/ : 1 /*immature*/;
  int invc = mdo->invocation_count();
  if (invc == 0 && mdo->backedge_count() > 0) invc = 1;
  out->print("MethodData %s %s %s %d %d", kname, mname, sig, state, invc);
}

static void dump_orig(fileStream* out, MethodData* mdo) {

  // orig header bytes: copy MethodData::CompilerCounters
  size_t cc_offset = in_bytes(MethodData::trap_history_offset()) - in_bytes(MethodData::CompilerCounters::trap_history_offset());
  const unsigned char* orig = (const unsigned char*)((address)mdo + cc_offset);
  int orig_len = (int)sizeof(MethodData::CompilerCounters);
  out->print(" orig %d", orig_len);
  for (int i = 0; i < orig_len; i++) {
    out->print(" %d", orig[i]);
  }
}

static void dump_cells(fileStream* out, MethodData* mdo) {
  // Dump raw data words: data + extra_data
  int elements = (mdo->data_size() + mdo->extra_data_size()) / (int)sizeof(intptr_t);
  out->print(" data %d", elements);
  intptr_t* base = (intptr_t*)mdo->data_base();
  for (int i = 0; i < elements; i++) {
    out->print(" 0x%zx", base[i]);
  }
}

// Small helpers to avoid duplication when collecting Klass* cells
static void add_klass_cell_if_in_bounds(MethodData* mdo,
                                        address base_dp,
                                        int off_bytes,
                                        Klass* k,
                                        int elements,
                                        GrowableArray<int>& class_offsets,
                                        GrowableArray<Klass*>& class_klasses) {
  if (k == nullptr) return;
  int di_bytes = mdo->dp_to_di(base_dp + off_bytes);
  int off_cells = di_bytes / (int)sizeof(intptr_t);
  if (0 <= off_cells && off_cells < elements) {
    class_offsets.push(off_cells);
    class_klasses.push(k);
  }
}

static void add_typeentry_if_present(MethodData* mdo,
                                     address base_dp,
                                     int off_bytes,
                                     int elements,
                                     GrowableArray<int>& class_offsets,
                                     GrowableArray<Klass*>& class_klasses) {
  intptr_t val = *(intptr_t*)(base_dp + off_bytes);
  Klass* k = TypeEntries::valid_klass(val);
  add_klass_cell_if_in_bounds(mdo, base_dp, off_bytes, k, elements, class_offsets, class_klasses);
}

 

static void collect_oops_and_methods(MethodData* mdo,
                                     GrowableArray<int>& class_offsets,
                                     GrowableArray<Klass*>& class_klasses,
                                     GrowableArray<int>& method_offsets,
                                     GrowableArray<Method*>& method_targets) {
  const int elements = (mdo->data_size() + mdo->extra_data_size()) / (int)sizeof(intptr_t);
  for (ProfileData* pd = mdo->first_data(); mdo->is_valid(pd); pd = mdo->next_data(pd)) {
    if (pd->is_VirtualCallData()) {
      VirtualCallData* vcd = pd->as_VirtualCallData();
      for (uint row = 0; row < vcd->row_limit(); row++) {
        Klass* k = vcd->receiver(row);
        add_klass_cell_if_in_bounds(mdo, pd->dp(), in_bytes(VirtualCallData::receiver_offset(row)), k,
                                    elements, class_offsets, class_klasses);
      }
    }
    if (pd->is_CallTypeData()) {
      CallTypeData* ctd = (CallTypeData*)pd;
      if (ctd->has_arguments()) {
        for (int i = 0; i < ctd->number_of_arguments(); i++) {
          add_typeentry_if_present(mdo, pd->dp(), in_bytes(ctd->argument_type_offset(i)),
                                   elements, class_offsets, class_klasses);
        }
      }
      if (ctd->has_return()) {
        add_typeentry_if_present(mdo, pd->dp(), in_bytes(ctd->return_type_offset()),
                                 elements, class_offsets, class_klasses);
      }
    }
    if (pd->is_VirtualCallTypeData()) {
      VirtualCallTypeData* vctd = pd->as_VirtualCallTypeData();
      if (vctd->has_arguments()) {
        for (int i = 0; i < vctd->number_of_arguments(); i++) {
          add_typeentry_if_present(mdo, pd->dp(), in_bytes(vctd->argument_type_offset(i)),
                                   elements, class_offsets, class_klasses);
        }
      }
      if (vctd->has_return()) {
        add_typeentry_if_present(mdo, pd->dp(), in_bytes(vctd->return_type_offset()),
                                 elements, class_offsets, class_klasses);
      }
    }
  }
  if (mdo->parameters_type_data() != nullptr) {
    ParametersTypeData* p = mdo->parameters_type_data();
    address p_dp = p->dp();
    for (int i = 0; i < p->number_of_parameters(); i++) {
      add_typeentry_if_present(mdo, p_dp, in_bytes(ParametersTypeData::type_offset(i)),
                               elements, class_offsets, class_klasses);
    }
  }
}

static void write_oops_and_methods(fileStream* out,
                                   GrowableArray<int>& class_offsets,
                                   GrowableArray<Klass*>& class_klasses,
                                   GrowableArray<int>& method_offsets,
                                   GrowableArray<Method*>& method_targets) {
  out->print(" oops %d", class_offsets.length());
  for (int i = 0; i < class_offsets.length(); i++) {
    Klass* k = class_klasses.at(i);
    const char* cname = k->name()->as_quoted_ascii();
    out->print(" %d %s", class_offsets.at(i), cname);
  }
  out->print(" methods %d", method_offsets.length());
  for (int i = 0; i < method_offsets.length(); i++) {
    Method* tm = method_targets.at(i);
    InstanceKlass* th = tm->method_holder();
    out->print(" %d %s %s %s", method_offsets.at(i), th->name()->as_quoted_ascii(), tm->name()->as_quoted_ascii(), tm->signature()->as_quoted_ascii());
  }
  out->cr();
}

static void dump_one_mdo(fileStream* out, Method* m, MethodData* mdo) {
  dump_header(out, m, mdo);
  dump_orig(out, mdo);
  dump_cells(out, mdo);
  GrowableArray<int> class_offsets(16);
  GrowableArray<Klass*> class_klasses(16);
  GrowableArray<int> method_offsets(4);
  GrowableArray<Method*> method_targets(4);
  collect_oops_and_methods(mdo, class_offsets, class_klasses, method_offsets, method_targets);
  // Note: we intentionally skip dumping extra_data trap records to avoid tag mismatches on load
  write_oops_and_methods(out, class_offsets, class_klasses, method_offsets, method_targets);
}

static const char* dump_path() { return MDOReplayDumpFile; }

void MDOReplayDump::dump_all(fileStream* out) {
  ResourceMark rm;
  log_info(compilation)("MDO replay: dumping MDOs");
  GrowableArray<Method*> methods(1024);
  g_methods = &methods;
  SystemDictionary::methods_do(collect_with_mdo);
  g_methods = nullptr;
  int emitted = 0;
  for (int i = 0; i < methods.length(); i++) {
    Method* m = methods.at(i);
    MethodData* mdo = m->method_data();
    if (mdo == nullptr) continue;
    if (!mdo->is_mature()) continue; // dump only stable profiles
    MutexLocker ml(mdo->extra_data_lock(), Mutex::_no_safepoint_check_flag);
    dump_one_mdo(out, m, mdo);
    emitted++;
  }
  log_info(compilation)("MDO replay: dumped %d MDOs", emitted);
}


