#ifndef SHARE_SERVICES_PROFILECHECKPOINT_HPP
#define SHARE_SERVICES_PROFILECHECKPOINT_HPP

#include "utilities/globalDefinitions.hpp"
#include <stdio.h>
#include "utilities/growableArray.hpp"

class fileStream;

class ProfileCheckpoint {
public:
    // Binary format v3 (File = [HEADER][SYMTAB][RECORDS])
    // HEADER:
    //   magic[4] = 'M','D','O','X'
    //   pointer_size: u16 (e.g., 8)
    //   endianness  : u16 (0=little, 1=big)
    //   layout flags: see LayoutFlags
    //   sym_count   : u32
    //   rec_count   : u32
    //   class_count : u32
    //
    // SYMTAB: repeated sym_count times
    //   [u32 len][len bytes utf8]
    //
    // CLASS: repeated class_count times:
    //   [u4 loader_id][u4 klass_sym_id]
    // 
    // RECORD: repeated rec_count times
    //   klass_id:u32, name_id:u32, sig_id:u32, loader:u8, mdo_size:u32,
    //   fixup_count:u32, Fixup[fixup_count], [mdo_size bytes]

  enum class LoaderId : u1 { BOOT, PLATFORM, SYSTEM, UNDEFINED, HIDDEN };

  struct SymbolId { uint32_t id; };

  struct Fixup {
    uint32_t offset_in_mdo;
    SymbolId  target;
    LoaderId  loader;
  };

  struct ByteRange { uint64_t off; uint32_t size; };

  struct LayoutFlags {
    uint32_t type_profile_level;
    int32_t  type_profile_args_limit;
    int32_t  type_profile_parms_limit;
    int64_t  type_profile_width;
    uint8_t  profile_traps;
    uint8_t  type_profile_casts;
    int32_t  spec_trap_limit_extra_entries;
  };

  struct MethodKey {
    LoaderId  loader;
    SymbolId  klass; // "a/b/C"
    SymbolId  name;  // "foo"
    SymbolId  sig;   // "(I)Ljava/lang/String;"
    uint32_t  bytecode_crc32;
  };

  struct Descriptor {
    MethodKey key;
    ByteRange mdo_payload {0,0};
    ByteRange mdo_fixups  {0,0};
    ByteRange mc_payload  {0,0};
    ByteRange mc_fixups   {0,0};
  };

  // Minimal metadata per-record used during dump before IDs are frozen
  struct RecMeta {
    const char* kname;
    const char* mname;
    const char* sig;
    u4          mdo_size;
    const void* mdo_ptr;
    u1          comp_level;
  };

  struct Header {
    char magic[4];
    u2   pointer_size;
    u2   endianness;
    LayoutFlags layout;
    u4   sym_count;
    u4   rec_count;
    u4   class_count;

    static void init(Header& h, u4 sym_count, u4 rec_count, u4 class_count);
    static bool write(fileStream* out, const Header& h);
    static bool read(FILE* in, Header& h);
  };

  struct Class {
    LoaderId loader;
    SymbolId klass;
  };

  struct Record {
    MethodKey key;
    u4        mdo_size;
    u4        fixup_count;
    u4        header_size;
    u4        mc_size; // bytes of MethodCounters snapshot (may be 0)
    u1        comp_level;

    static bool write(fileStream* out, const Record& r, const void* mdo_bytes,
                      const Fixup* fixups, const void* mc_bytes, const void* header_bytes);
    static bool read(FILE* in, Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes, char*& header_bytes);
  };

  class BinaryStreamWriter {
    fileStream* _out;
  public:
    explicit BinaryStreamWriter(fileStream* out) : _out(out) {}
    bool write_header(u4 sym_count, u4 rec_count, u4 class_count);
    bool write_symtab(const GrowableArray<const char*>& symbols) const;
    bool write_classes(const GrowableArray<Class>& classes) const;
    bool write_record(const Record& r, const void* mdo_bytes,
                      const Fixup* fixups, const void* mc_bytes, const void* header_bytes) const;
  };

  class BinaryStreamReader {
    FILE* _in;
  public:
    explicit BinaryStreamReader(FILE* in) : _in(in) {}
    bool read_header(Header& h) const;
    bool read_symtab(GrowableArray<char*>& symbols, u4 expected) const;
    bool read_classes(GrowableArray<Class>& classes, u4 expected) const;
    bool read_record(Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes, char*& header_bytes) const;
  };

  class SymtabBuilder {
  private:
    GrowableArray<const char*> _syms;
    bool                        _frozen;
  public:
    SymtabBuilder() : _syms(256), _frozen(false) {}
    u4 intern(const char* s);
    u4 id_of(const char* s) const;
    void freeze() { _frozen = true; }
    u4 length() const { return (u4)_syms.length(); }
    const GrowableArray<const char*>& symbols() const { return _syms; }
  };

  class Loader {
  public:
    enum class LoadStatus {
      Success,
      MissingPath,
      FileOpenFailed,
      HeaderInvalid,
      SymtabReadFailed,
      RecordReadFailed
    };

    struct LoadResult {
      LoadStatus status;
      int records_read;
      int records_installed;
      int size_mismatch;
      bool ok() const { return status == LoadStatus::Success; }
    };

    explicit Loader(class JavaThread* thread);
    LoadResult load_from_file(const char* path);
    static const char* load_status_name(LoadStatus status);
    static bool dump_to_stream(fileStream* out);
  private:
    class JavaThread* _thread;
    int _records_read;
    int _records_installed;
    int _size_mismatch;

    bool install_record(const Record& rec,
                        Fixup* fixups,
                        char* mdo_bytes,
                        char* mc_bytes,
                        char* header_bytes,
                        GrowableArray<char*>& symtab);
  };

  static void load(class JavaThread* THREAD);
  static void dump_to_stream(class fileStream* out);
  static void wait_for_compile_completion(class JavaThread* THREAD);
  static void scan_hidden_class_locators();
};

#endif // SHARE_SERVICES_PROFILECHECKPOINT_HPP
