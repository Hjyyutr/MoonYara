// Mach-O binary format parsing

///|
pub(all) struct MachOHeader {
  magic : Int
  cputype : Int
  cpusubtype : Int
  filetype : Int
  ncmds : Int
  sizeofcmds : Int
  flags : Int
} derive(Eq, Debug)

///|
pub(all) struct MachOSegment {
  segname : String
  vmaddr : Int64
  vmsize : Int64
  fileoff : Int64
  filesize : Int64
  nsects : Int
} derive(Eq, Debug)

///|
pub(all) struct MachOInfo {
  is_macho : Bool
  header : MachOHeader
  segments : Array[MachOSegment]
  cputype : Int
  filetype : Int
} derive(Eq, Debug)

///|
fn MachOHeader::default() -> MachOHeader {
  MachOHeader::{
    magic: 0,
    cputype: 0,
    cpusubtype: 0,
    filetype: 0,
    ncmds: 0,
    sizeofcmds: 0,
    flags: 0,
  }
}

///|
pub fn MachOInfo::default() -> MachOInfo {
  MachOInfo::{
    is_macho: false,
    header: MachOHeader::default(),
    segments: [],
    cputype: 0,
    filetype: 0,
  }
}

///|
priv struct SafeMachoReader {
  data : Bytes
  mut offset : Int
  mut is_be : Bool
}

///|
fn SafeMachoReader::new(data : Bytes) -> SafeMachoReader {
  SafeMachoReader::{ data, offset: 0, is_be: false }
}

///|
fn SafeMachoReader::read_u8(self : SafeMachoReader) -> Byte {
  if self.offset >= self.data.length() || self.offset < 0 {
    return (0).to_byte()
  }
  let b = self.data[self.offset]
  self.offset += 1
  b
}

///|
fn SafeMachoReader::read_u32(self : SafeMachoReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  let b2 = self.read_u8().to_int()
  let b3 = self.read_u8().to_int()
  if self.is_be {
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  } else {
    (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
  }
}

///|
fn SafeMachoReader::read_u64(self : SafeMachoReader) -> Int64 {
  let b0 = self.read_u8().to_int64()
  let b1 = self.read_u8().to_int64()
  let b2 = self.read_u8().to_int64()
  let b3 = self.read_u8().to_int64()
  let b4 = self.read_u8().to_int64()
  let b5 = self.read_u8().to_int64()
  let b6 = self.read_u8().to_int64()
  let b7 = self.read_u8().to_int64()
  if self.is_be {
    (b0 << 56) |
    (b1 << 48) |
    (b2 << 40) |
    (b3 << 32) |
    (b4 << 24) |
    (b5 << 16) |
    (b6 << 8) |
    b7
  } else {
    (b7 << 56) |
    (b6 << 48) |
    (b5 << 40) |
    (b4 << 32) |
    (b3 << 24) |
    (b2 << 16) |
    (b1 << 8) |
    b0
  }
}

///|
pub fn parse_macho(data : Bytes) -> MachOInfo {
  if data.length() < 28 {
    return MachOInfo::default()
  }
  let magic = (data[0].to_int() << 24) |
    (data[1].to_int() << 16) |
    (data[2].to_int() << 8) |
    data[3].to_int()
  let mut is_macho = false
  let mut is_be = false
  let mut is_64 = false
  if magic == 0xfeedface {
    is_macho = true
    is_be = true
    is_64 = false
  } else if magic == 0xcefaedfe {
    is_macho = true
    is_be = false
    is_64 = false
  } else if magic == 0xfeedfacf {
    is_macho = true
    is_be = true
    is_64 = true
  } else if magic == 0xcffaedfe {
    is_macho = true
    is_be = false
    is_64 = true
  }
  if !is_macho {
    return MachOInfo::default()
  }

  let reader = SafeMachoReader::new(data)
  reader.is_be = is_be
  reader.offset = 4

  let cputype = reader.read_u32()
  let cpusubtype = reader.read_u32()
  let filetype = reader.read_u32()
  let ncmds = reader.read_u32()
  let sizeofcmds = reader.read_u32()
  let flags = reader.read_u32()
  if is_64 {
    let _reserved = reader.read_u32()
  }

  let header = MachOHeader::{
    magic,
    cputype,
    cpusubtype,
    filetype,
    ncmds,
    sizeofcmds,
    flags,
  }

  let segments = []
  let mut cmd_offset = if is_64 { 32 } else { 28 }
  for _i in 0..<ncmds {
    if cmd_offset + 8 > data.length() || cmd_offset < 0 {
      break
    }
    reader.offset = cmd_offset
    let cmd = reader.read_u32()
    let cmdsize = reader.read_u32()
    if cmd_offset + cmdsize > data.length() || cmdsize < 8 {
      break
    }

    if cmd == 1 || cmd == 0x19 {
      let is_seg64 = cmd == 0x19
      reader.offset = cmd_offset + 8
      let name_bytes = [
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
        reader.read_u8(),
      ]
      let mut name_len = 0
      while name_len < 16 && name_bytes[name_len] != (0).to_byte() {
        name_len += 1
      }
      let name_chars = name_bytes[0:name_len].map(fn(b) {
        match b.to_int().to_char() {
          Some(c) => c
          None => '\u{0000}'
        }
      })
      let segname = String::from_array(name_chars)

      let mut vmaddr = 0L
      let mut vmsize = 0L
      let mut fileoff = 0L
      let mut filesize = 0L
      let mut nsects = 0
      if is_seg64 {
        vmaddr = reader.read_u64()
        vmsize = reader.read_u64()
        fileoff = reader.read_u64()
        filesize = reader.read_u64()
        let _maxprot = reader.read_u32()
        let _initprot = reader.read_u32()
        nsects = reader.read_u32()
      } else {
        vmaddr = reader.read_u32().to_int64()
        vmsize = reader.read_u32().to_int64()
        fileoff = reader.read_u32().to_int64()
        filesize = reader.read_u32().to_int64()
        let _maxprot = reader.read_u32()
        let _initprot = reader.read_u32()
        nsects = reader.read_u32()
      }

      segments.push(MachOSegment::{
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        nsects,
      })
    }
    cmd_offset += cmdsize
  }

  MachOInfo::{ is_macho: true, header, segments, cputype, filetype }
}
