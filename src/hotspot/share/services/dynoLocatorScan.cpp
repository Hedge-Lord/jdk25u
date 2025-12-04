#include "services/dynoLocatorScan.hpp"

#include "classfile/javaClasses.hpp"
#include "classfile/vmClasses.hpp"
#include "ci/ciReplay.hpp"
#include "interpreter/bytecodeStream.hpp"
#include "memory/resourceArea.hpp"
#include "oops/constantPool.inline.hpp"
#include "oops/cpCache.inline.hpp"
#include "oops/instanceKlass.hpp"
#include "oops/method.hpp"
#include "oops/oop.inline.hpp"
#include "oops/resolvedIndyEntry.hpp"
#include "oops/symbol.hpp"
#include "prims/methodHandles.hpp"
#include "runtime/handles.inline.hpp"
#include "runtime/thread.hpp"
#include "runtime/thread.inline.hpp"
#include "runtime/threads.hpp"
#include "runtime/mutex.hpp"
#include "runtime/mutexLocker.hpp"
#include "runtime/os.hpp"
#include "runtime/threadSMR.hpp"
#include "utilities/growableArray.hpp"
#include "utilities/ostream.hpp"
#include <cstdarg>
#include <cstring>

namespace {

// Limit borrowed from ciEnv::_dyno_name
static const int LOC_BUF_LEN = 1024;

class DynoLocatorTable {
  class Entry {
  public:
    InstanceKlass* _ik;
    const char*    _loc;
    Entry() : _ik(nullptr), _loc(nullptr) {}
    Entry(InstanceKlass* ik, const char* loc) : _ik(ik), _loc(loc) {}
  };
  static GrowableArray<Entry>* _entries;
  static Mutex* _lock;
  static void ensure_init() {
    if (_entries == nullptr) {
      _entries = new (mtInternal) GrowableArray<Entry>(8, mtInternal);
    }
    if (_lock == nullptr) {
      _lock = new Mutex(Mutex::nosafepoint, "DynoLocatorTable");
    }
  }
public:
  static void record(InstanceKlass* ik, const char* loc) {
    log_debug(compilation)("recording ik: %s with name %s", ik->name()->as_utf8(), loc);
    if (ik == nullptr || loc == nullptr) return;
    ensure_init();
    MutexLocker ml(_lock, Mutex::_no_safepoint_check_flag);
    for (int i = 0; i < _entries->length(); i++) {
      if (_entries->at(i)._ik == ik) return;
    }
    const char* copy = os::strdup(loc, mtInternal);
    _entries->append(Entry(ik, copy));
  }
  static const char* lookup(InstanceKlass* ik) {
    if (_entries == nullptr || ik == nullptr) return nullptr;
    MutexLocker ml(_lock, Mutex::_no_safepoint_check_flag);
    for (int i = 0; i < _entries->length(); i++) {
      if (_entries->at(i)._ik == ik) return _entries->at(i)._loc;
    }
    return nullptr;
  }
};

GrowableArray<DynoLocatorTable::Entry>* DynoLocatorTable::_entries = nullptr;
Mutex* DynoLocatorTable::_lock = nullptr;

class RecordLocation {
  char* _start;
  char* _end;
  char* _buf;
public:
  ATTRIBUTE_PRINTF(3, 4)
  RecordLocation(char* buf, const char* fmt, ...) {
    _buf = buf;
    _start = _buf + (int)strlen(_buf);
    va_list args;
    va_start(args, fmt);
    _end = _start + os::vsnprintf(_start, LOC_BUF_LEN - (_start - _buf), fmt, args);
    va_end(args);
    if (_end >= _buf + LOC_BUF_LEN) {
      _end = _buf + LOC_BUF_LEN - 1;
      *_end = '\0';
    }
  }
  ~RecordLocation() {
    *_start = '\0';
  }
};

static void record_hidden(InstanceKlass* ik, const char* loc) {
  if (ik != nullptr && ik->is_hidden() && loc != nullptr) {
    DynoLocatorTable::record(ik, loc);
  }
}

static void record_call_site_obj(JavaThread* jt, oop obj, char* loc_buf);

static void record_member(JavaThread* jt, oop member, char* loc_buf) {
  assert(java_lang_invoke_MemberName::is_instance(member), "!");
  oop clazz = java_lang_invoke_MemberName::clazz(member);
  if (clazz != nullptr && clazz->klass()->is_instance_klass()) {
    RecordLocation rl(loc_buf, " clazz");
    InstanceKlass* ik = InstanceKlass::cast(clazz->klass());
    record_hidden(ik, loc_buf);
  }
  Method* vmtarget = java_lang_invoke_MemberName::vmtarget(member);
  if (vmtarget != nullptr) {
    RecordLocation rl(loc_buf, " <vmtarget>");
    InstanceKlass* ik = vmtarget->method_holder();
    record_hidden(ik, loc_buf);
  }
}

static void record_mh(JavaThread* jt, oop mh, char* loc_buf) {
  assert(java_lang_invoke_MethodHandle::is_instance(mh), "!");
  if (java_lang_invoke_DirectMethodHandle::is_instance(mh)) {
    oop member = java_lang_invoke_DirectMethodHandle::member(mh);
    RecordLocation rl(loc_buf, " member");
    record_member(jt, member, loc_buf);
    return;
  }

  // For BoundMethodHandle and friends, scan argL* fields.
  char arg_name[] = " argLXX";
  const int max_arg = 99;
  for (int index = 0; index <= max_arg; ++index) {
    jio_snprintf(arg_name, sizeof(arg_name), " argL%d", index);
    oop arg = ciReplay::obj_field(mh, arg_name + 1); // reuse helper to read field
    if (arg != nullptr) {
      RecordLocation rl(loc_buf, "%s", arg_name);
      if (arg->klass()->is_instance_klass()) {
        InstanceKlass* ik = InstanceKlass::cast(arg->klass());
        record_hidden(ik, loc_buf);
        record_call_site_obj(jt, arg, loc_buf);
      }
    } else {
      break;
    }
  }
}

static void record_call_site_obj(JavaThread* jt, oop obj, char* loc_buf) {
  if (obj == nullptr) {
    return;
  }
  if (java_lang_invoke_MethodHandle::is_instance(obj)) {
    record_mh(jt, obj, loc_buf);
  } else if (java_lang_invoke_ConstantCallSite::is_instance(obj)) {
    oop target = java_lang_invoke_CallSite::target(obj);
    if (target != nullptr && target->klass()->is_instance_klass()) {
      RecordLocation rl(loc_buf, " target");
      InstanceKlass* ik = InstanceKlass::cast(target->klass());
      record_hidden(ik, loc_buf);
      record_call_site_obj(jt, target, loc_buf);
    }
  }
}

static void record_call_site_method(JavaThread* jt, Method* adapter, char* loc_buf) {
  if (adapter == nullptr) return;
  InstanceKlass* holder = adapter->method_holder();
  if (!holder->is_hidden()) return;
  RecordLocation rl(loc_buf, " <adapter>");
  record_hidden(holder, loc_buf);
}

static void process_invokedynamic(const constantPoolHandle& cp, int indy_index, JavaThread* jt, char* loc_buf) {
  ResolvedIndyEntry* indy_info = cp->resolved_indy_entry_at(indy_index);
  if (indy_info == nullptr || indy_info->method() == nullptr) {
    return;
  }
  // adapter
  Method* adapter = indy_info->method();
  record_call_site_method(jt, adapter, loc_buf);
  // appendix
  oop appendix = cp->resolved_reference_from_indy(indy_index);
  {
    RecordLocation rl(loc_buf, " <appendix>");
    record_call_site_obj(jt, appendix, loc_buf);
  }
  // BSM
  int pool_index = indy_info->constant_pool_index();
  BootstrapInfo bootstrap_specifier(cp, pool_index, indy_index);
  oop bsm = cp->resolve_possibly_cached_constant_at(bootstrap_specifier.bsm_index(), jt);
  {
    RecordLocation rl(loc_buf, " <bsm>");
    record_call_site_obj(jt, bsm, loc_buf);
  }
}

static void process_invokehandle(const constantPoolHandle& cp, int index, JavaThread* jt, char* loc_buf) {
  const int holder_index = cp->klass_ref_index_at(index, Bytecodes::_invokehandle);
  if (!cp->tag_at(holder_index).is_klass()) {
    return;  // not resolved
  }
  Klass* holder = ConstantPool::klass_at_if_loaded(cp, holder_index);
  Symbol* name = cp->name_ref_at(index, Bytecodes::_invokehandle);
  if (MethodHandles::is_signature_polymorphic_name(holder, name)) {
    ResolvedMethodEntry* method_entry = cp->resolved_method_entry_at(index);
    if (method_entry->is_resolved(Bytecodes::_invokehandle)) {
      Method* adapter = method_entry->method();
      oop appendix = cp->cache()->appendix_if_resolved(method_entry);
      record_call_site_method(jt, adapter, loc_buf);
      {
        RecordLocation rl(loc_buf, " <appendix>");
        record_call_site_obj(jt, appendix, loc_buf);
      }
    }
  }
}

} // anonymous namespace

void DynoLocatorScan::scan_all_classes() {
  ResourceMark rm;
  char loc_buf[LOC_BUF_LEN];
  loc_buf[0] = '\0';

  Thread* thread = Thread::current();
  JavaThread* jt = thread->is_Java_thread() ? JavaThread::cast(thread) : nullptr;
  if (jt == nullptr) {
    // Fallback: use any alive JavaThread as context.
    JavaThreadIteratorWithHandle jtiwh;
    for (JavaThread* t = jtiwh.next(); t != nullptr; t = jtiwh.next()) {
      if (!t->is_terminated()) { jt = t; break; }
    }
  }
  if (jt == nullptr) {
    log_debug(compilation)("dls: no JavaThread available");
    return; // cannot walk without a JavaThread context
  }

  for (ClassHierarchyIterator iter(vmClasses::Object_klass()); !iter.done(); iter.next()) {
    Klass* k = iter.klass();
    if (!k->is_instance_klass()) continue;
    InstanceKlass* ik = InstanceKlass::cast(k);
    if (!ik->is_linked()) continue;
    if (ik->is_hidden()) continue; // only scan non-hidden sources


    const constantPoolHandle cp(jt, ik->constants());
    Array<Method*>* methods = ik->methods();
    for (int mi = 0; mi < methods->length(); mi++) {
      Method* m = methods->at(mi);
      BytecodeStream bcs(methodHandle(jt, m));
      while (!bcs.is_last_bytecode()) {
        Bytecodes::Code opcode = bcs.next();
        opcode = bcs.raw_code();
        if (opcode == Bytecodes::_invokedynamic || opcode == Bytecodes::_invokehandle) {
          RecordLocation rl(loc_buf, "@bci %s %s %s %d",
                           ik->name()->as_quoted_ascii(),
                           m->name()->as_quoted_ascii(),
                           m->signature()->as_quoted_ascii(),
                           bcs.bci());
          if (opcode == Bytecodes::_invokedynamic) {
            int index = bcs.get_index_u4();
            process_invokedynamic(cp, index, jt, loc_buf);
          } else {
            int cp_cache_index = bcs.get_index_u2();
            process_invokehandle(cp, cp_cache_index, jt, loc_buf);
          }
        }
      }
    }
  }
}

const char* DynoLocatorScan::lookup(InstanceKlass* ik) {
  return DynoLocatorTable::lookup(ik);
}
