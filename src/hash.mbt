// MD5 implementation in MoonBit

///|
pub(all) struct HashInfo {
  is_active : Bool
}

///|
pub fn HashInfo::default() -> HashInfo {
  HashInfo::{ is_active: true }
}

///|
fn f_f(x : Int, y : Int, z : Int) -> Int {
  (x & y) | ((x ^ -1) & z)
}

///|
fn f_g(x : Int, y : Int, z : Int) -> Int {
  (x & z) | (y & (z ^ -1))
}

///|
fn f_h(x : Int, y : Int, z : Int) -> Int {
  x ^ y ^ z
}

///|
fn f_i(x : Int, y : Int, z : Int) -> Int {
  y ^ (x | (z ^ -1))
}

///|
fn rotate_left(x : Int, n : Int) -> Int {
  (x << n) | ((x >> (32 - n)) & ((1 << n) - 1))
}

///|
fn md5_step(
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : Int,
  s : Int,
  t : Int,
  f : (Int, Int, Int) -> Int,
) -> Int {
  let sum = a + f(b, c, d) + x + t
  rotate_left(sum, s) + b
}

///|
fn read_word(data : Array[Byte], offset : Int) -> Int {
  let b0 = data[offset].to_int()
  let b1 = data[offset + 1].to_int()
  let b2 = data[offset + 2].to_int()
  let b3 = data[offset + 3].to_int()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///|
pub fn calculate_md5(data : Bytes, offset : Int, size : Int) -> String {
  if size < 0 || offset < 0 || offset + size > data.length() {
    return ""
  }

  // 1. Prepare padding
  let mut padded_len = size + 1
  while padded_len % 64 != 56 {
    padded_len += 1
  }
  padded_len += 8

  let padded = Array::make(padded_len, (0).to_byte())
  for i in 0..<size {
    padded[i] = data[offset + i]
  }
  padded[size] = (0x80).to_byte()

  // Set bit length at the end (little endian)
  let bits_len = size.to_int64() * 8L
  let len_offset = padded_len - 8
  padded[len_offset] = bits_len.to_int().to_byte()
  padded[len_offset + 1] = (bits_len >> 8).to_int().to_byte()
  padded[len_offset + 2] = (bits_len >> 16).to_int().to_byte()
  padded[len_offset + 3] = (bits_len >> 24).to_int().to_byte()
  padded[len_offset + 4] = (bits_len >> 32).to_int().to_byte()
  padded[len_offset + 5] = (bits_len >> 40).to_int().to_byte()
  padded[len_offset + 6] = (bits_len >> 48).to_int().to_byte()
  padded[len_offset + 7] = (bits_len >> 56).to_int().to_byte()

  // 2. MD5 Constants
  let t = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
  ]

  // Initialize buffer
  let mut h0 = 0x67452301
  let mut h1 = 0xefcdab89
  let mut h2 = 0x98badcfe
  let mut h3 = 0x10325476

  // 3. Process blocks
  let num_blocks = padded_len / 64
  let w = Array::make(16, 0)
  for b in 0..<num_blocks {
    let block_offset = b * 64
    for i in 0..<16 {
      w[i] = read_word(padded, block_offset + i * 4)
    }

    let mut a = h0
    let mut d = h1
    let mut c = h2
    let mut g = h3

    // Round 1
    a = md5_step(a, d, c, g, w[0], 7, t[0], f_f)
    g = md5_step(g, a, d, c, w[1], 12, t[1], f_f)
    c = md5_step(c, g, a, d, w[2], 17, t[2], f_f)
    d = md5_step(d, c, g, a, w[3], 22, t[3], f_f)
    a = md5_step(a, d, c, g, w[4], 7, t[4], f_f)
    g = md5_step(g, a, d, c, w[5], 12, t[5], f_f)
    c = md5_step(c, g, a, d, w[6], 17, t[6], f_f)
    d = md5_step(d, c, g, a, w[7], 22, t[7], f_f)
    a = md5_step(a, d, c, g, w[8], 7, t[8], f_f)
    g = md5_step(g, a, d, c, w[9], 12, t[9], f_f)
    c = md5_step(c, g, a, d, w[10], 17, t[10], f_f)
    d = md5_step(d, c, g, a, w[11], 22, t[11], f_f)
    a = md5_step(a, d, c, g, w[12], 7, t[12], f_f)
    g = md5_step(g, a, d, c, w[13], 12, t[13], f_f)
    c = md5_step(c, g, a, d, w[14], 17, t[14], f_f)
    d = md5_step(d, c, g, a, w[15], 22, t[15], f_f)

    // Round 2
    a = md5_step(a, d, c, g, w[1], 5, t[16], f_g)
    g = md5_step(g, a, d, c, w[6], 9, t[17], f_g)
    c = md5_step(c, g, a, d, w[11], 14, t[18], f_g)
    d = md5_step(d, c, g, a, w[0], 20, t[19], f_g)
    a = md5_step(a, d, c, g, w[5], 5, t[20], f_g)
    g = md5_step(g, a, d, c, w[10], 9, t[21], f_g)
    c = md5_step(c, g, a, d, w[15], 14, t[22], f_g)
    d = md5_step(d, c, g, a, w[4], 20, t[23], f_g)
    a = md5_step(a, d, c, g, w[9], 5, t[24], f_g)
    g = md5_step(g, a, d, c, w[14], 9, t[25], f_g)
    c = md5_step(c, g, a, d, w[3], 14, t[26], f_g)
    d = md5_step(d, c, g, a, w[8], 20, t[27], f_g)
    a = md5_step(a, d, c, g, w[13], 5, t[28], f_g)
    g = md5_step(g, a, d, c, w[2], 9, t[29], f_g)
    c = md5_step(c, g, a, d, w[7], 14, t[30], f_g)
    d = md5_step(d, c, g, a, w[12], 20, t[31], f_g)

    // Round 3
    a = md5_step(a, d, c, g, w[5], 4, t[32], f_h)
    g = md5_step(g, a, d, c, w[8], 11, t[33], f_h)
    c = md5_step(c, g, a, d, w[11], 16, t[34], f_h)
    d = md5_step(d, c, g, a, w[14], 23, t[35], f_h)
    a = md5_step(a, d, c, g, w[1], 4, t[36], f_h)
    g = md5_step(g, a, d, c, w[4], 11, t[37], f_h)
    c = md5_step(c, g, a, d, w[7], 16, t[38], f_h)
    d = md5_step(d, c, g, a, w[10], 23, t[39], f_h)
    a = md5_step(a, d, c, g, w[13], 4, t[40], f_h)
    g = md5_step(g, a, d, c, w[0], 11, t[41], f_h)
    c = md5_step(c, g, a, d, w[3], 16, t[42], f_h)
    d = md5_step(d, c, g, a, w[6], 23, t[43], f_h)
    a = md5_step(a, d, c, g, w[9], 4, t[44], f_h)
    g = md5_step(g, a, d, c, w[12], 11, t[45], f_h)
    c = md5_step(c, g, a, d, w[15], 16, t[46], f_h)
    d = md5_step(d, c, g, a, w[2], 23, t[47], f_h)

    // Round 4
    a = md5_step(a, d, c, g, w[0], 6, t[48], f_i)
    g = md5_step(g, a, d, c, w[7], 10, t[49], f_i)
    c = md5_step(c, g, a, d, w[14], 15, t[50], f_i)
    d = md5_step(d, c, g, a, w[5], 21, t[51], f_i)
    a = md5_step(a, d, c, g, w[12], 6, t[52], f_i)
    g = md5_step(g, a, d, c, w[3], 10, t[53], f_i)
    c = md5_step(c, g, a, d, w[10], 15, t[54], f_i)
    d = md5_step(d, c, g, a, w[1], 21, t[55], f_i)
    a = md5_step(a, d, c, g, w[8], 6, t[56], f_i)
    g = md5_step(g, a, d, c, w[15], 10, t[57], f_i)
    c = md5_step(c, g, a, d, w[6], 15, t[58], f_i)
    d = md5_step(d, c, g, a, w[13], 21, t[59], f_i)
    a = md5_step(a, d, c, g, w[4], 6, t[60], f_i)
    g = md5_step(g, a, d, c, w[11], 10, t[61], f_i)
    c = md5_step(c, g, a, d, w[2], 15, t[62], f_i)
    d = md5_step(d, c, g, a, w[9], 21, t[63], f_i)

    h0 += a
    h1 += d
    h2 += c
    h3 += g
  }

  // Convert h0, h1, h2, h3 to hex string (little endian)
  fn to_hex(val : Int) -> String {
    let hex_chars = [
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
      'f',
    ]
    let mut s = ""
    for b in 0..<4 {
      let byte_val = (val >> (b * 8)) & 0xff
      let h1_idx = byte_val >> 4
      let h2_idx = byte_val & 0x0f
      s += String::from_array([hex_chars[h1_idx]]) +
        String::from_array([hex_chars[h2_idx]])
    }
    s
  }

  to_hex(h0) + to_hex(h1) + to_hex(h2) + to_hex(h3)
}

///|
pub fn base64_encode(data : Bytes, offset : Int, size : Int) -> String {
  if size < 0 || offset < 0 || offset + size > data.length() {
    return ""
  }
  let b64_chars = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
  ]
  let mut s = ""
  let mut i = 0
  while i < size {
    let b0 = data[offset + i].to_int()
    let b1 = if i + 1 < size { data[offset + i + 1].to_int() } else { 0 }
    let b2 = if i + 2 < size { data[offset + i + 2].to_int() } else { 0 }

    let w0 = b0 >> 2
    let w1 = ((b0 & 3) << 4) | (b1 >> 4)
    let w2 = ((b1 & 15) << 2) | (b2 >> 6)
    let w3 = b2 & 63

    s += String::from_array([b64_chars[w0]]) +
      String::from_array([b64_chars[w1]])
    if i + 1 < size {
      s += String::from_array([b64_chars[w2]])
    } else {
      s += "="
    }
    if i + 2 < size {
      s += String::from_array([b64_chars[w3]])
    } else {
      s += "="
    }
    i += 3
  }
  s
}

///|
pub fn calculate_crc32(data : Bytes, offset : Int, size : Int) -> Int {
  if size < 0 || offset < 0 || offset + size > data.length() {
    return 0
  }
  let poly = 0xEDB88320
  let table = Array::make(256, 0)
  for i in 0..<256 {
    let mut crc = i
    for _j in 0..<8 {
      if (crc & 1) != 0 {
        crc = ((crc >> 1) & 0x7FFFFFFF) ^ poly
      } else {
        crc = (crc >> 1) & 0x7FFFFFFF
      }
    }
    table[i] = crc
  }

  let mut current_crc = -1
  for i in 0..<size {
    let index = (current_crc ^ data[offset + i].to_int()) & 0xff
    current_crc = ((current_crc >> 8) & 0x00FFFFFF) ^ table[index]
  }
  current_crc ^ -1
}

///|
pub fn base64_decode(s : String) -> Bytes {
  let b64_chars = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
  ]
  let decode_table = Array::make(256, -1)
  for i in 0..<64 {
    decode_table[b64_chars[i].to_int()] = i
  }

  let mut clean_len = 0
  let mut padding = 0
  for i in 0..<s.length() {
    let c = s[i].to_int()
    if c == '='.to_int() {
      padding += 1
    } else if c >= 0 && c < 256 && decode_table[c] != -1 {
      clean_len += 1
    }
  }

  let total_len = clean_len + padding
  if total_len == 0 || total_len % 4 != 0 {
    return Bytes::new(0)
  }

  let out_len = (clean_len + padding) / 4 * 3 - padding
  let out = Array::make(out_len, (0).to_byte())

  let mut out_idx = 0
  let mut buffer = 0
  let mut bits = 0
  for i in 0..<s.length() {
    let c = s[i].to_int()
    if c >= 0 && c < 256 {
      let val = decode_table[c]
      if val != -1 {
        buffer = (buffer << 6) | val
        bits += 6
        if bits >= 8 {
          bits -= 8
          if out_idx < out_len {
            out[out_idx] = ((buffer >> bits) & 0xff).to_byte()
            out_idx += 1
          }
        }
      }
    }
  }

  Bytes::from_array(out)
}
