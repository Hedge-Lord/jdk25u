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
   //   version     : u32 (==3)
   //   pointer_size: u16 (e.g., 8)
   //   endianness  : u16 (0=little, 1=big)
   //   layout flags: see LayoutFlags
   //   sym_count   : u32
   //   rec_count   : u32
  //
  // SYMTAB: repeated sym_count times
  //   [u32 len][len bytes utf8]
  //
   // RECORD: repeated rec_count times
   //   klass_id:u32, name_id:u32, sig_id:u32, loader:u8, mdo_size:u32,
   //   fixup_count:u32, Fixup[fixup_count], [mdo_size bytes]

  enum class LoaderId : u1 { BOOT, PLATFORM, APP, UNDEFINED };
  enum class FixupKind : u1 { KLASS, METHOD };

  struct SymbolId { uint32_t id; };

  struct Fixup {
    uint32_t offset_in_mdo;
    FixupKind kind;
    SymbolId  target;
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
  };

   struct Header {
    char magic[4];
    u4   version;
     u2   pointer_size;
     u2   endianness;
     LayoutFlags layout;
    u4   sym_count;
    u4   rec_count;

    static void init(Header& h, u4 sym_count, u4 rec_count);
    static bool write(fileStream* out, const Header& h);
    static bool read(FILE* in, Header& h);
  };

   struct Record {
     MethodKey key;
     u4        mdo_size;
     u4        fixup_count;
     u4        mc_size; // bytes of MethodCounters snapshot (may be 0)

     static bool write(fileStream* out, const Record& r, const void* mdo_bytes,
                       const Fixup* fixups, const void* mc_bytes);
     static bool read(FILE* in, Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes);
   };

  class Writer {
    fileStream* _out;
  public:
    explicit Writer(fileStream* out) : _out(out) {}
    bool write_header(u4 sym_count, u4 rec_count) { Header h; Header::init(h, sym_count, rec_count); return Header::write(_out, h); }
    bool write_record(const Record& r, const void* mdo_bytes, const Fixup* fixups, const void* mc_bytes) { return Record::write(_out, r, mdo_bytes, fixups, mc_bytes); }
  };

  class Reader {
    FILE* _in;
  public:
    explicit Reader(FILE* in) : _in(in) {}
    bool read_header(Header& h) { return Header::read(_in, h); }
    bool read_record(Record& r, Fixup*& fixups, char*& mdo_bytes, char*& mc_bytes) { return Record::read(_in, r, fixups, mdo_bytes, mc_bytes); }
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
    bool write(fileStream* out) const;
  };

  static void load(class JavaThread* THREAD);
  static void dump_to_stream(class fileStream* out);
};

#endif // SHARE_SERVICES_PROFILECHECKPOINT_HPP
