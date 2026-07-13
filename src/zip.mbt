// ZIP format parsing

///|
pub(all) struct ZipLocalFile {
  filename : String
  compressed_size : Int
  uncompressed_size : Int
  compression_method : Int
} derive(Eq, Debug)

///|
pub(all) struct ZipInfo {
  is_zip : Bool
  files : Array[ZipLocalFile]
  number_of_files : Int
} derive(Eq, Debug)

///|
pub fn ZipInfo::default() -> ZipInfo {
  ZipInfo::{ is_zip: false, files: [], number_of_files: 0 }
}

///|
priv struct SafeZipReader {
  data : Bytes
  mut offset : Int
}

///|
fn SafeZipReader::new(data : Bytes) -> SafeZipReader {
  SafeZipReader::{ data, offset: 0 }
}

///|
fn SafeZipReader::read_u8(self : SafeZipReader) -> Byte {
  if self.offset >= self.data.length() || self.offset < 0 {
    return (0).to_byte()
  }
  let b = self.data[self.offset]
  self.offset += 1
  b
}

///|
fn SafeZipReader::read_u16_le(self : SafeZipReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  (b1 << 8) | b0
}

///|
fn SafeZipReader::read_u32_le(self : SafeZipReader) -> Int {
  let b0 = self.read_u8().to_int()
  let b1 = self.read_u8().to_int()
  let b2 = self.read_u8().to_int()
  let b3 = self.read_u8().to_int()
  (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
}

///|
pub fn parse_zip(data : Bytes) -> ZipInfo {
  if data.length() < 30 {
    return ZipInfo::default()
  }
  // Check local file header signature PK\x03\x04 (0x50, 0x4b, 0x03, 0x04)
  if data[0] != 0x50 || data[1] != 0x4b {
    return ZipInfo::default()
  }

  let files = []
  let reader = SafeZipReader::new(data)
  reader.offset = 0

  while reader.offset + 30 <= data.length() {
    let sig = reader.read_u32_le()
    if sig == 0x04034b50 {
      // Local File Header
      let _version_needed = reader.read_u16_le()
      let _flags = reader.read_u16_le()
      let compression_method = reader.read_u16_le()
      let _last_mod_time = reader.read_u16_le()
      let _last_mod_date = reader.read_u16_le()
      let _crc32 = reader.read_u32_le()
      let compressed_size = reader.read_u32_le()
      let uncompressed_size = reader.read_u32_le()
      let filename_len = reader.read_u16_le()
      let extra_field_len = reader.read_u16_le()
      if reader.offset + filename_len + extra_field_len > data.length() ||
        filename_len < 0 {
        break
      }

      // Read filename
      let filename_bytes = []
      for _i in 0..<filename_len {
        filename_bytes.push(reader.read_u8())
      }
      let filename_chars = filename_bytes.map(fn(b) {
        match b.to_int().to_char() {
          Some(c) => c
          None => '\u{0000}'
        }
      })
      let filename = String::from_array(filename_chars)
      reader.offset += extra_field_len // Skip extra fields
      reader.offset += compressed_size // Skip compressed data

      files.push(ZipLocalFile::{
        filename,
        compressed_size,
        uncompressed_size,
        compression_method,
      })
    } else {
      break
    }
  }

  ZipInfo::{ is_zip: true, files, number_of_files: files.length() }
}
