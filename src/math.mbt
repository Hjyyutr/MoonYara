// Math module for YARA engine: Shannon entropy, mean, deviation, etc.

///|
fn ln(x : Double) -> Double {
  if x <= 0.0 {
    return 0.0
  }
  // ln(x) = 2 * atanh((x-1)/(x+1))
  // atanh(z) = z + z^3/3 + z^5/5 + z^7/7 ...
  let z = (x - 1.0) / (x + 1.0)
  let z2 = z * z
  let mut term = z
  let mut sum = z
  let mut denom = 1.0
  for _i in 0..<10 {
    denom += 2.0
    term *= z2
    sum += term / denom
  }
  2.0 * sum
}

///|
fn sqrt(x : Double) -> Double {
  if x <= 0.0 {
    return 0.0
  }
  let mut g = x / 2.0
  for _i in 0..<10 {
    g = (g + x / g) / 2.0
  }
  g
}

///|
pub(all) struct MathInfo {
  is_active : Bool
}

///|
pub fn MathInfo::default() -> MathInfo {
  MathInfo::{ is_active: true }
}

///|
pub fn calculate_entropy(data : Bytes, offset : Int, size : Int) -> Double {
  if size <= 0 || offset < 0 || offset + size > data.length() {
    return 0.0
  }
  let counts = Array::make(256, 0)
  for i in 0..<size {
    let b = data[offset + i].to_int()
    counts[b] += 1
  }
  let mut ent = 0.0
  let len = size.to_double()
  let ln2 = 0.6931471805599453
  for i in 0..<256 {
    if counts[i] > 0 {
      let p = counts[i].to_double() / len
      let lnp = ln(p)
      ent -= p * (lnp / ln2)
    }
  }
  ent
}

///|
pub fn calculate_mean(data : Bytes, offset : Int, size : Int) -> Double {
  if size <= 0 || offset < 0 || offset + size > data.length() {
    return 0.0
  }
  let mut sum = 0.0
  for i in 0..<size {
    sum += data[offset + i].to_int().to_double()
  }
  sum / size.to_double()
}

///|
pub fn calculate_deviation(
  data : Bytes,
  offset : Int,
  size : Int,
  mean_val : Double,
) -> Double {
  if size <= 0 || offset < 0 || offset + size > data.length() {
    return 0.0
  }
  let mut sum = 0.0
  for i in 0..<size {
    let diff = data[offset + i].to_int().to_double() - mean_val
    sum += diff * diff
  }
  let variance = sum / size.to_double()
  sqrt(variance)
}
