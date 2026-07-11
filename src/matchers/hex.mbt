///| Labeled suberror for YARA parser/scanner failures.
pub(all) suberror YaraError {
  ValueError(String)
} derive(Eq, Debug)

///| Represents a single element in a hex pattern sequence, which can be an exact byte value or a wildcard.
pub(all) enum BytePattern {
  Byte(Byte)
  Wildcard
} derive(Eq, Debug)

///| Parses a hex digit (represented as UInt16 code unit) into its integer value.
fn parse_hex_digit(c : UInt16) -> Int? {
  let c_int = c.to_int()
  if c_int >= '0'.to_int() && c_int <= '9'.to_int() {
    Some(c_int - '0'.to_int())
  } else if c_int >= 'A'.to_int() && c_int <= 'F'.to_int() {
    Some(c_int - 'A'.to_int() + 10)
  } else if c_int >= 'a'.to_int() && c_int <= 'f'.to_int() {
    Some(c_int - 'a'.to_int() + 10)
  } else {
    None
  }
}

///| Parses a hex pattern string like "E2 34 ?? 90" or "{ E2 34 ?? 90 }" into an array of BytePattern.
pub fn parse_hex_pattern(pattern_str : String) -> Array[BytePattern] raise YaraError {
  let result = []
  let mut s = pattern_str.trim().to_owned()
  if s.has_prefix("{") {
    match s.strip_prefix("{") {
      Some(v) => s = v.to_owned()
      None => ()
    }
  }
  if s.has_suffix("}") {
    match s.strip_suffix("}") {
      Some(v) => s = v.to_owned()
      None => ()
    }
  }
  
  // split by spaces
  let parts = s.split(" ")
  for part in parts {
    let p = part.trim().to_owned()
    if p == "" {
      continue
    }
    if p == "??" || p == "?" {
      result.push(Wildcard)
    } else {
      if p.length() != 2 {
        raise YaraError::ValueError("Invalid hex pattern segment: " + p)
      }
      let high = match parse_hex_digit(p[0]) {
        Some(v) => v
        None => raise YaraError::ValueError("Invalid hex digit: " + p[0:1].to_owned())
      }
      let low = match parse_hex_digit(p[1]) {
        Some(v) => v
        None => raise YaraError::ValueError("Invalid hex digit: " + p[1:2].to_owned())
      }
      let val = (high << 4) | low
      result.push(Byte(val.to_byte()))
    }
  }
  result
}

///| Scans a byte stream (Bytes) for the given hex pattern.
/// Returns the array of matching start offsets.
pub fn match_hex(pattern : Array[BytePattern], data : Bytes) -> Array[Int] {
  let matches = []
  if pattern.length() == 0 || data.length() < pattern.length() {
    return matches
  }
  let limit = data.length() - pattern.length()
  for offset in 0..=limit {
    let mut is_match = true
    for i in 0..<pattern.length() {
      match pattern[i] {
        Byte(b) => if data[offset + i] != b {
          is_match = false
          break
        }
        Wildcard => ()
      }
    }
    if is_match {
      matches.push(offset)
    }
  }
  matches
}
