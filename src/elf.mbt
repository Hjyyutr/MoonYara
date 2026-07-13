// ELF parsing logic

///|
pub(all) struct ElfHeader {
  class_ : Int
  data_encoding : Int
  version : Int
  os_abi : Int
  abi_version : Int
  type_ : Int
  machine : Int
  entry_point : Int64
  ph_off : Int64
  sh_off : Int64
  flags : Int
  eh_size : Int
  ph_ent_size : Int
  ph_num : Int
  sh_ent_size : Int
  sh_num : Int
  sh_str_nd : Int
} derive(Eq, Debug)

///|
pub(all) struct ElfProgramHeader {
  type_ : Int
  flags : Int
  offset : Int64
  vaddr : Int64
  paddr : Int64
  filesz : Int64
  memsz : Int64
  align : Int64
} derive(Eq, Debug)

///|
pub(all) struct ElfSectionHeader {
  name_index : Int
  type_ : Int
  flags : Int64
  addr : Int64
  offset : Int64
  size : Int64
  link : Int
  info : Int
  addralign : Int64
  entsize : Int64
} derive(Eq, Debug)

///|
pub(all) struct ElfInfo {
  is_elf : Bool
  header : ElfHeader
  program_headers : Array[ElfProgramHeader]
  sections : Array[ElfSectionHeader]
  entry_point : Int64
  number_of_sections : Int
  type_ : Int
  machine : Int
} derive(Eq, Debug)

///|
fn ElfHeader::default() -> ElfHeader {
  ElfHeader::{
    class_: 0,
    data_encoding: 0,
    version: 0,
    os_abi: 0,
    abi_version: 0,
    type_: 0,
    machine: 0,
    entry_point: 0L,
    ph_off: 0L,
    sh_off: 0L,
    flags: 0,
    eh_size: 0,
    ph_ent_size: 0,
    ph_num: 0,
    sh_ent_size: 0,
    sh_num: 0,
    sh_str_nd: 0,
  }
}

///|
pub fn ElfInfo::default() -> ElfInfo {
  ElfInfo::{
    is_elf: false,
    header: ElfHeader::default(),
    program_headers: [],
    sections: [],
    entry_point: 0L,
    number_of_sections: 0,
    type_: 0,
    machine: 0,
  }
}

///|
priv struct SafeElfReader {
  data : Bytes
  mut offset : Int
  mut is_be : Bool
}

///|
fn SafeElfReader::new(data : Bytes) -> SafeElfReader {
  SafeElfReader::{ data, offset: 0, is_be: false }
}

///|
fn SafeElfReader::read_u8(self : SafeElfReader) -> Byte {
  if self.offset >= self.data.length() || self.offset < 0 {
    return 0
  }
  let b = self.data[self.offset]
  self.offset += 1
  b
}

///|
fn SafeElfReader::read_u16(self : SafeElfReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  if self.is_be {
    (b0 << 8) | b1
  } else {
    (b1 << 8) | b0
  }
}

///|
fn SafeElfReader::read_u32(self : SafeElfReader) -> Int {
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
fn SafeElfReader::read_u64(self : SafeElfReader) -> Int64 {
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
pub fn parse_elf(data : Bytes) -> ElfInfo {
  if data.length() < 52 {
    return ElfInfo::default()
  }
  // Check magic signature \x7fELF
  if data[0] != 0x7f || data[1] != 0x45 || data[2] != 0x4c || data[3] != 0x46 {
    return ElfInfo::default()
  }

  let class_ = data[4].to_int()
  let data_encoding = data[5].to_int()
  let version = data[6].to_int()
  let os_abi = data[7].to_int()
  let abi_version = data[8].to_int()

  let is_be = data_encoding == 2
  let reader = SafeElfReader::new(data)
  reader.is_be = is_be

  reader.offset = 16
  let type_ = reader.read_u16()
  let machine = reader.read_u16()
  let _version2 = reader.read_u32()

  let mut entry_point = 0L
  let mut ph_off = 0L
  let mut sh_off = 0L
  let mut flags = 0
  let mut eh_size = 0
  let mut ph_ent_size = 0
  let mut ph_num = 0
  let mut sh_ent_size = 0
  let mut sh_num = 0
  let mut sh_str_nd = 0

  if class_ == 1 {
    // 32-bit ELF Header
    entry_point = reader.read_u32().to_int64()
    ph_off = reader.read_u32().to_int64()
    sh_off = reader.read_u32().to_int64()
    flags = reader.read_u32()
    eh_size = reader.read_u16()
    ph_ent_size = reader.read_u16()
    ph_num = reader.read_u16()
    sh_ent_size = reader.read_u16()
    sh_num = reader.read_u16()
    sh_str_nd = reader.read_u16()
  } else if class_ == 2 {
    // 64-bit ELF Header
    if data.length() < 64 {
      return ElfInfo::default()
    }
    entry_point = reader.read_u64()
    ph_off = reader.read_u64()
    sh_off = reader.read_u64()
    flags = reader.read_u32()
    eh_size = reader.read_u16()
    ph_ent_size = reader.read_u16()
    ph_num = reader.read_u16()
    sh_ent_size = reader.read_u16()
    sh_num = reader.read_u16()
    sh_str_nd = reader.read_u16()
  } else {
    return ElfInfo::default()
  }

  let header = ElfHeader::{
    class_,
    data_encoding,
    version,
    os_abi,
    abi_version,
    type_,
    machine,
    entry_point,
    ph_off,
    sh_off,
    flags,
    eh_size,
    ph_ent_size,
    ph_num,
    sh_ent_size,
    sh_num,
    sh_str_nd,
  }

  // Parse Program Headers
  let program_headers = []
  if ph_off > 0L && ph_num > 0 && ph_ent_size > 0 {
    let mut ph_offset = ph_off.to_int()
    for _i in 0..<ph_num {
      if ph_offset + ph_ent_size > data.length() || ph_offset < 0 {
        break
      }
      reader.offset = ph_offset
      let mut p_type = 0
      let mut p_flags = 0
      let mut p_offset = 0L
      let mut p_vaddr = 0L
      let mut p_paddr = 0L
      let mut p_filesz = 0L
      let mut p_memsz = 0L
      let mut p_align = 0L

      if class_ == 1 {
        p_type = reader.read_u32()
        p_offset = reader.read_u32().to_int64()
        p_vaddr = reader.read_u32().to_int64()
        p_paddr = reader.read_u32().to_int64()
        p_filesz = reader.read_u32().to_int64()
        p_memsz = reader.read_u32().to_int64()
        p_flags = reader.read_u32()
        p_align = reader.read_u32().to_int64()
      } else {
        p_type = reader.read_u32()
        p_flags = reader.read_u32()
        p_offset = reader.read_u64()
        p_vaddr = reader.read_u64()
        p_paddr = reader.read_u64()
        p_filesz = reader.read_u64()
        p_memsz = reader.read_u64()
        p_align = reader.read_u64()
      }

      program_headers.push(ElfProgramHeader::{
        type_: p_type,
        flags: p_flags,
        offset: p_offset,
        vaddr: p_vaddr,
        paddr: p_paddr,
        filesz: p_filesz,
        memsz: p_memsz,
        align: p_align,
      })
      ph_offset += ph_ent_size
    }
  }

  // Parse Section Headers
  let sections = []
  if sh_off > 0L && sh_num > 0 && sh_ent_size > 0 {
    let mut sh_offset = sh_off.to_int()
    for _i in 0..<sh_num {
      if sh_offset + sh_ent_size > data.length() || sh_offset < 0 {
        break
      }
      reader.offset = sh_offset
      let mut s_name = 0
      let mut s_type = 0
      let mut s_flags = 0L
      let mut s_addr = 0L
      let mut s_offset = 0L
      let mut s_size = 0L
      let mut s_link = 0
      let mut s_info = 0
      let mut s_addralign = 0L
      let mut s_entsize = 0L

      if class_ == 1 {
        s_name = reader.read_u32()
        s_type = reader.read_u32()
        s_flags = reader.read_u32().to_int64()
        s_addr = reader.read_u32().to_int64()
        s_offset = reader.read_u32().to_int64()
        s_size = reader.read_u32().to_int64()
        s_link = reader.read_u32()
        s_info = reader.read_u32()
        s_addralign = reader.read_u32().to_int64()
        s_entsize = reader.read_u32().to_int64()
      } else {
        s_name = reader.read_u32()
        s_type = reader.read_u32()
        s_flags = reader.read_u64()
        s_addr = reader.read_u64()
        s_offset = reader.read_u64()
        s_size = reader.read_u64()
        s_link = reader.read_u32()
        s_info = reader.read_u32()
        s_addralign = reader.read_u64()
        s_entsize = reader.read_u64()
      }

      sections.push(ElfSectionHeader::{
        name_index: s_name,
        type_: s_type,
        flags: s_flags,
        addr: s_addr,
        offset: s_offset,
        size: s_size,
        link: s_link,
        info: s_info,
        addralign: s_addralign,
        entsize: s_entsize,
      })
      sh_offset += sh_ent_size
    }
  }

  ElfInfo::{
    is_elf: true,
    header,
    program_headers,
    sections,
    entry_point,
    number_of_sections: sh_num,
    type_,
    machine,
  }
}
