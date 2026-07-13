///|
/// Evaluation context containing match status for each string variable.
pub(all) struct MatchContext {
  matched_vars : Map[String, Bool]
  all_vars : Array[String]
  filesize : Int
  pe : PeInfo
  elf : ElfInfo
  macho : MachOInfo
  zip : ZipInfo
  data : Bytes
}

///|
/// Evaluates a YaraExpression using the MatchContext.
pub fn evaluate_expression(
  expr : YaraExpression,
  ctx : MatchContext,
) -> YaraValue {
  match expr {
    FileSize => IntVal(ctx.filesize)
    IntLiteral(val) => IntVal(val)
    StringLiteral(val) => StrVal(val)
    Add(left, right) =>
      match (evaluate_expression(left, ctx), evaluate_expression(right, ctx)) {
        (IntVal(l), IntVal(r)) => IntVal(l + r)
        _ => NoneVal
      }
    Sub(left, right) =>
      match (evaluate_expression(left, ctx), evaluate_expression(right, ctx)) {
        (IntVal(l), IntVal(r)) => IntVal(l - r)
        _ => NoneVal
      }
    Mul(left, right) =>
      match (evaluate_expression(left, ctx), evaluate_expression(right, ctx)) {
        (IntVal(l), IntVal(r)) => IntVal(l * r)
        _ => NoneVal
      }
    Div(left, right) =>
      match (evaluate_expression(left, ctx), evaluate_expression(right, ctx)) {
        (IntVal(l), IntVal(r)) => if r == 0 { NoneVal } else { IntVal(l / r) }
        _ => NoneVal
      }
    ModuleMember(mod_name, field_name) =>
      match mod_name {
        "pe" =>
          match field_name {
            "entry_point" => IntVal(ctx.pe.entry_point)
            "number_of_sections" => IntVal(ctx.pe.number_of_sections)
            "machine" => IntVal(ctx.pe.machine)
            _ => NoneVal
          }
        "elf" =>
          match field_name {
            "entry_point" => IntVal(ctx.elf.entry_point.to_int())
            "number_of_sections" => IntVal(ctx.elf.number_of_sections)
            "machine" => IntVal(ctx.elf.machine)
            "type" => IntVal(ctx.elf.type_)
            _ => NoneVal
          }
        "macho" =>
          match field_name {
            "cputype" => IntVal(ctx.macho.cputype)
            "filetype" => IntVal(ctx.macho.filetype)
            _ => NoneVal
          }
        "zip" =>
          match field_name {
            "number_of_files" => IntVal(ctx.zip.number_of_files)
            _ => NoneVal
          }
        _ => NoneVal
      }
    ModuleMemberIndex(mod_name, coll_name, index_expr, field_name) => {
      let idx_val = evaluate_expression(index_expr, ctx)
      match idx_val {
        IntVal(idx) =>
          match mod_name {
            "pe" =>
              match coll_name {
                "sections" =>
                  if idx >= 0 && idx < ctx.pe.sections.length() {
                    let sec = ctx.pe.sections[idx]
                    match field_name {
                      "name" => StrVal(sec.name)
                      "virtual_size" => IntVal(sec.virtual_size)
                      "virtual_address" => IntVal(sec.virtual_address)
                      "size_of_raw_data" => IntVal(sec.size_of_raw_data)
                      _ => NoneVal
                    }
                  } else {
                    NoneVal
                  }
                _ => NoneVal
              }
            "elf" =>
              match coll_name {
                "sections" =>
                  if idx >= 0 && idx < ctx.elf.sections.length() {
                    let sec = ctx.elf.sections[idx]
                    match field_name {
                      "name_index" => IntVal(sec.name_index)
                      "type" => IntVal(sec.type_)
                      "addr" => IntVal(sec.addr.to_int())
                      "size" => IntVal(sec.size.to_int())
                      _ => NoneVal
                    }
                  } else {
                    NoneVal
                  }
                _ => NoneVal
              }
            "macho" =>
              match coll_name {
                "segments" =>
                  if idx >= 0 && idx < ctx.macho.segments.length() {
                    let seg = ctx.macho.segments[idx]
                    match field_name {
                      "segname" => StrVal(seg.segname)
                      "vmaddr" => IntVal(seg.vmaddr.to_int())
                      "vmsize" => IntVal(seg.vmsize.to_int())
                      "filesize" => IntVal(seg.filesize.to_int())
                      _ => NoneVal
                    }
                  } else {
                    NoneVal
                  }
                _ => NoneVal
              }
            "zip" =>
              match coll_name {
                "files" =>
                  if idx >= 0 && idx < ctx.zip.files.length() {
                    let f = ctx.zip.files[idx]
                    match field_name {
                      "filename" => StrVal(f.filename)
                      "compressed_size" => IntVal(f.compressed_size)
                      "uncompressed_size" => IntVal(f.uncompressed_size)
                      "compression_method" => IntVal(f.compression_method)
                      _ => NoneVal
                    }
                  } else {
                    NoneVal
                  }
                _ => NoneVal
              }
            _ => NoneVal
          }
        _ => NoneVal
      }
    }
    ModuleMethodCall(mod_name, method_name, args) => {
      let arg_vals = args.map(fn(arg) { evaluate_expression(arg, ctx) })
      match mod_name {
        "math" =>
          match method_name {
            "entropy" =>
              if arg_vals.length() == 2 {
                match (arg_vals[0], arg_vals[1]) {
                  (IntVal(offset), IntVal(size)) => {
                    let ent = calculate_entropy(ctx.data, offset, size)
                    IntVal((ent * 100.0).to_int())
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            "mean" =>
              if arg_vals.length() == 2 {
                match (arg_vals[0], arg_vals[1]) {
                  (IntVal(offset), IntVal(size)) => {
                    let m = calculate_mean(ctx.data, offset, size)
                    IntVal(m.to_int())
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            "deviation" =>
              if arg_vals.length() == 3 {
                match (arg_vals[0], arg_vals[1], arg_vals[2]) {
                  (IntVal(offset), IntVal(size), IntVal(mean_val)) => {
                    let d = calculate_deviation(
                      ctx.data,
                      offset,
                      size,
                      mean_val.to_double(),
                    )
                    IntVal(d.to_int())
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            _ => NoneVal
          }
        "hash" =>
          match method_name {
            "md5" =>
              if arg_vals.length() == 2 {
                match (arg_vals[0], arg_vals[1]) {
                  (IntVal(offset), IntVal(size)) => {
                    let h = calculate_md5(ctx.data, offset, size)
                    StrVal(h)
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            "crc32" =>
              if arg_vals.length() == 2 {
                match (arg_vals[0], arg_vals[1]) {
                  (IntVal(offset), IntVal(size)) => {
                    let c = calculate_crc32(ctx.data, offset, size)
                    IntVal(c)
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            "base64" =>
              if arg_vals.length() == 2 {
                match (arg_vals[0], arg_vals[1]) {
                  (IntVal(offset), IntVal(size)) => {
                    let b = base64_encode(ctx.data, offset, size)
                    StrVal(b)
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            "base64_decode" =>
              if arg_vals.length() == 1 {
                match arg_vals[0] {
                  StrVal(str) => {
                    let decoded_bytes = base64_decode(str)
                    let mut decoded_str = ""
                    for i in 0..<decoded_bytes.length() {
                      match decoded_bytes[i].to_int().to_char() {
                        Some(c) => decoded_str += String::from_array([c])
                        None => ()
                      }
                    }
                    StrVal(decoded_str)
                  }
                  _ => NoneVal
                }
              } else {
                NoneVal
              }
            _ => NoneVal
          }
        _ => NoneVal
      }
    }
  }
}

///|
/// Evaluates a YaraCondition using the MatchContext.
pub fn evaluate_condition(cond : YaraCondition, ctx : MatchContext) -> Bool {
  match cond {
    True => true
    False => false
    StringRef(name) => ctx.matched_vars.get_or_default(name, false)
    And(left, right) =>
      evaluate_condition(left, ctx) && evaluate_condition(right, ctx)
    Or(left, right) =>
      evaluate_condition(left, ctx) || evaluate_condition(right, ctx)
    Not(child) => !evaluate_condition(child, ctx)
    Compare(op, left, right) => {
      let l_val = evaluate_expression(left, ctx)
      let r_val = evaluate_expression(right, ctx)
      match (l_val, r_val) {
        (IntVal(l), IntVal(r)) =>
          match op {
            Eq => l == r
            NotEq => l != r
            Lt => l < r
            LtEq => l <= r
            Gt => l > r
            GtEq => l >= r
          }
        (StrVal(l), StrVal(r)) =>
          match op {
            Eq => l == r
            NotEq => l != r
            _ => false
          }
        (BoolVal(l), BoolVal(r)) =>
          match op {
            Eq => l == r
            NotEq => l != r
            _ => false
          }
        _ => false
      }
    }
    AnyOfThem => {
      let mut matched = false
      for v in ctx.all_vars {
        if ctx.matched_vars.get_or_default(v, false) {
          matched = true
          break
        }
      }
      matched
    }
    AllOfThem => {
      let mut matched = true
      for v in ctx.all_vars {
        if !ctx.matched_vars.get_or_default(v, false) {
          matched = false
          break
        }
      }
      matched
    }
    Of(expr, list) => {
      let limit_val = evaluate_expression(expr, ctx)
      match limit_val {
        IntVal(limit) => {
          let mut count = 0
          for v in list {
            if ctx.matched_vars.get_or_default(v, false) {
              count += 1
            }
          }
          count >= limit
        }
        _ => false
      }
    }
  }
}
