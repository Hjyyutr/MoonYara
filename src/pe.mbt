// PE / COFF parsing logic

///|
pub(all) struct PeHeader {
  machine : Int
  number_of_sections : Int
  time_date_stamp : Int
  pointer_to_symbol_table : Int
  number_of_symbols : Int
  size_of_optional_header : Int
  characteristics : Int
} derive(Eq, Debug)

///|
pub(all) struct PeOptionalHeader {
  magic : Int
  major_linker_version : Int
  minor_linker_version : Int
  size_of_code : Int
  size_of_initialized_data : Int
  size_of_uninitialized_data : Int
  address_of_entry_point : Int
  base_of_code : Int
  image_base : Int64
  section_alignment : Int
  file_alignment : Int
  major_operating_system_version : Int
  minor_operating_system_version : Int
  major_image_version : Int
  minor_image_version : Int
  major_subsystem_version : Int
  minor_subsystem_version : Int
  win32_version_value : Int
  size_of_image : Int
  size_of_headers : Int
  check_sum : Int
  subsystem : Int
  dll_characteristics : Int
  size_of_stack_reserve : Int64
  size_of_stack_commit : Int64
  size_of_heap_reserve : Int64
  size_of_heap_commit : Int64
  loader_flags : Int
  number_of_rva_and_sizes : Int
} derive(Eq, Debug)

///|
pub(all) struct PeSection {
  name : String
  virtual_size : Int
  virtual_address : Int
  size_of_raw_data : Int
  pointer_to_raw_data : Int
  pointer_to_relocations : Int
  pointer_to_linenumbers : Int
  number_of_relocations : Int
  number_of_linenumbers : Int
  characteristics : Int
} derive(Eq, Debug)

///|
pub(all) struct PeInfo {
  is_pe : Bool
  header : PeHeader
  optional_header : PeOptionalHeader
  sections : Array[PeSection]
  entry_point : Int
  number_of_sections : Int
  machine : Int
} derive(Eq, Debug)

///|
fn PeHeader::default() -> PeHeader {
  PeHeader::{
    machine: 0,
    number_of_sections: 0,
    time_date_stamp: 0,
    pointer_to_symbol_table: 0,
    number_of_symbols: 0,
    size_of_optional_header: 0,
    characteristics: 0,
  }
}

///|
fn PeOptionalHeader::default() -> PeOptionalHeader {
  PeOptionalHeader::{
    magic: 0,
    major_linker_version: 0,
    minor_linker_version: 0,
    size_of_code: 0,
    size_of_initialized_data: 0,
    size_of_uninitialized_data: 0,
    address_of_entry_point: 0,
    base_of_code: 0,
    image_base: 0L,
    section_alignment: 0,
    file_alignment: 0,
    major_operating_system_version: 0,
    minor_operating_system_version: 0,
    major_image_version: 0,
    minor_image_version: 0,
    major_subsystem_version: 0,
    minor_subsystem_version: 0,
    win32_version_value: 0,
    size_of_image: 0,
    size_of_headers: 0,
    check_sum: 0,
    subsystem: 0,
    dll_characteristics: 0,
    size_of_stack_reserve: 0L,
    size_of_stack_commit: 0L,
    size_of_heap_reserve: 0L,
    size_of_heap_commit: 0L,
    loader_flags: 0,
    number_of_rva_and_sizes: 0,
  }
}

///|
pub fn PeInfo::default() -> PeInfo {
  PeInfo::{
    is_pe: false,
    header: PeHeader::default(),
    optional_header: PeOptionalHeader::default(),
    sections: [],
    entry_point: 0,
    number_of_sections: 0,
    machine: 0,
  }
}

///|
priv struct SafeReader {
  data : Bytes
  mut offset : Int
}

///|
fn SafeReader::new(data : Bytes) -> SafeReader {
  SafeReader::{ data, offset: 0 }
}

///|
fn SafeReader::read_u8(self : SafeReader) -> Byte {
  if self.offset >= self.data.length() || self.offset < 0 {
    return 0
  }
  let b = self.data[self.offset]
  self.offset += 1
  b
}

///|
fn SafeReader::read_u16_le(self : SafeReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  (b1 << 8) | b0
}

///|
fn SafeReader::read_u32_le(self : SafeReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  let b2 = self.read_u8().to_int()
  let b3 = self.read_u8().to_int()
  (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
}

///|
fn SafeReader::read_u64_le(self : SafeReader) -> Int64 {
  let b0 = self.read_u8().to_int64()
  let b1 = self.read_u8().to_int64()
  let b2 = self.read_u8().to_int64()
  let b3 = self.read_u8().to_int64()
  let b4 = self.read_u8().to_int64()
  let b5 = self.read_u8().to_int64()
  let b6 = self.read_u8().to_int64()
  let b7 = self.read_u8().to_int64()
  (b7 << 56) |
  (b6 << 48) |
  (b5 << 40) |
  (b4 << 32) |
  (b3 << 24) |
  (b2 << 16) |
  (b1 << 8) |
  b0
}

///|
pub fn parse_pe(data : Bytes) -> PeInfo {
  if data.length() < 64 {
    return PeInfo::default()
  }
  // Check MZ signature
  if data[0] != 0x4d || data[1] != 0x5a {
    return PeInfo::default()
  }
  let reader = SafeReader::new(data)
  reader.offset = 0x3c
  let pe_offset = reader.read_u32_le()
  if pe_offset + 24 >= data.length() || pe_offset < 0 {
    return PeInfo::default()
  }

  // Verify PE signature
  if data[pe_offset] != 0x50 ||
    data[pe_offset + 1] != 0x45 ||
    data[pe_offset + 2] != 0 ||
    data[pe_offset + 3] != 0 {
    return PeInfo::default()
  }

  // Parse COFF Header
  reader.offset = pe_offset + 4
  let machine = reader.read_u16_le()
  let number_of_sections = reader.read_u16_le()
  let time_date_stamp = reader.read_u32_le()
  let pointer_to_symbol_table = reader.read_u32_le()
  let number_of_symbols = reader.read_u32_le()
  let size_of_optional_header = reader.read_u16_le()
  let characteristics = reader.read_u16_le()

  let header = PeHeader::{
    machine,
    number_of_sections,
    time_date_stamp,
    pointer_to_symbol_table,
    number_of_symbols,
    size_of_optional_header,
    characteristics,
  }

  // Parse Optional Header
  let opt_header_start = pe_offset + 24
  if opt_header_start + size_of_optional_header > data.length() {
    return PeInfo::default()
  }

  reader.offset = opt_header_start
  let magic = reader.read_u16_le()
  let major_linker_version = reader.read_u8().to_int()
  let minor_linker_version = reader.read_u8().to_int()
  let size_of_code = reader.read_u32_le()
  let size_of_initialized_data = reader.read_u32_le()
  let size_of_uninitialized_data = reader.read_u32_le()
  let address_of_entry_point = reader.read_u32_le()
  let base_of_code = reader.read_u32_le()

  let mut image_base = 0L
  let mut section_alignment = 0
  let mut file_alignment = 0
  let mut major_operating_system_version = 0
  let mut minor_operating_system_version = 0
  let mut major_image_version = 0
  let mut minor_image_version = 0
  let mut major_subsystem_version = 0
  let mut minor_subsystem_version = 0
  let mut win32_version_value = 0
  let mut size_of_image = 0
  let mut size_of_headers = 0
  let mut check_sum = 0
  let mut subsystem = 0
  let mut dll_characteristics = 0
  let mut size_of_stack_reserve = 0L
  let mut size_of_stack_commit = 0L
  let mut size_of_heap_reserve = 0L
  let mut size_of_heap_commit = 0L
  let mut loader_flags = 0
  let mut number_of_rva_and_sizes = 0

  if magic == 0x10b {
    // PE32 Optional Header fields
    image_base = reader.read_u32_le().to_int64()
    section_alignment = reader.read_u32_le()
    file_alignment = reader.read_u32_le()
    major_operating_system_version = reader.read_u16_le()
    minor_operating_system_version = reader.read_u16_le()
    major_image_version = reader.read_u16_le()
    minor_image_version = reader.read_u16_le()
    major_subsystem_version = reader.read_u16_le()
    minor_subsystem_version = reader.read_u16_le()
    win32_version_value = reader.read_u32_le()
    size_of_image = reader.read_u32_le()
    size_of_headers = reader.read_u32_le()
    check_sum = reader.read_u32_le()
    subsystem = reader.read_u16_le()
    dll_characteristics = reader.read_u16_le()
    size_of_stack_reserve = reader.read_u32_le().to_int64()
    size_of_stack_commit = reader.read_u32_le().to_int64()
    size_of_heap_reserve = reader.read_u32_le().to_int64()
    size_of_heap_commit = reader.read_u32_le().to_int64()
    loader_flags = reader.read_u32_le()
    number_of_rva_and_sizes = reader.read_u32_le()
  } else if magic == 0x20b {
    // PE32+ Optional Header fields
    section_alignment = reader.read_u32_le()
    file_alignment = reader.read_u32_le()
    major_operating_system_version = reader.read_u16_le()
    minor_operating_system_version = reader.read_u16_le()
    major_image_version = reader.read_u16_le()
    minor_image_version = reader.read_u16_le()
    major_subsystem_version = reader.read_u16_le()
    minor_subsystem_version = reader.read_u16_le()
    win32_version_value = reader.read_u32_le()
    size_of_image = reader.read_u32_le()
    size_of_headers = reader.read_u32_le()
    check_sum = reader.read_u32_le()
    subsystem = reader.read_u16_le()
    dll_characteristics = reader.read_u16_le()
    size_of_stack_reserve = reader.read_u64_le()
    size_of_stack_commit = reader.read_u64_le()
    size_of_heap_reserve = reader.read_u64_le()
    size_of_heap_commit = reader.read_u64_le()
    loader_flags = reader.read_u32_le()
    number_of_rva_and_sizes = reader.read_u32_le()
  }

  let optional_header = PeOptionalHeader::{
    magic,
    major_linker_version,
    minor_linker_version,
    size_of_code,
    size_of_initialized_data,
    size_of_uninitialized_data,
    address_of_entry_point,
    base_of_code,
    image_base,
    section_alignment,
    file_alignment,
    major_operating_system_version,
    minor_operating_system_version,
    major_image_version,
    minor_image_version,
    major_subsystem_version,
    minor_subsystem_version,
    win32_version_value,
    size_of_image,
    size_of_headers,
    check_sum,
    subsystem,
    dll_characteristics,
    size_of_stack_reserve,
    size_of_stack_commit,
    size_of_heap_reserve,
    size_of_heap_commit,
    loader_flags,
    number_of_rva_and_sizes,
  }

  // Parse Sections
  let sections = []
  let sections_start = opt_header_start + size_of_optional_header
  if sections_start + number_of_sections * 40 <= data.length() {
    for i in 0..<number_of_sections {
      reader.offset = sections_start + i * 40
      let name_bytes = [
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
      while name_len < 8 && name_bytes[name_len] != 0 {
        name_len += 1
      }
      let name_chars = name_bytes[0:name_len].map(fn(b) {
        match b.to_int().to_char() {
          Some(c) => c
          None => '\u{0000}'
        }
      })
      let name = String::from_array(name_chars)

      let virtual_size = reader.read_u32_le()
      let virtual_address = reader.read_u32_le()
      let size_of_raw_data = reader.read_u32_le()
      let pointer_to_raw_data = reader.read_u32_le()
      let pointer_to_relocations = reader.read_u32_le()
      let pointer_to_linenumbers = reader.read_u32_le()
      let number_of_relocations = reader.read_u16_le()
      let number_of_linenumbers = reader.read_u16_le()
      let characteristics = reader.read_u32_le()

      sections.push(PeSection::{
        name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        characteristics,
      })
    }
  }

  PeInfo::{
    is_pe: true,
    header,
    optional_header,
    sections,
    entry_point: address_of_entry_point,
    number_of_sections,
    machine,
  }
}
