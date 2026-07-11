///|
fn main {
  let args = @env.args()

  if args.length() < 5 {
    print_usage()
    return
  }

  let mut rule_file = ""
  let mut target_file = ""

  let mut i = 1
  while i < args.length() {
    if args[i] == "-r" && i + 1 < args.length() {
      rule_file = args[i + 1]
      i += 2
    } else if args[i] == "-f" && i + 1 < args.length() {
      target_file = args[i + 1]
      i += 2
    } else {
      i += 1
    }
  }

  if rule_file == "" || target_file == "" {
    print_usage()
    return
  }

  try {
    println("Loading YARA rules from: " + rule_file)
    let rules_content = @fs.read_file_to_string(rule_file)
    let compiled = @src.compile_rules(rules_content)

    println("Scanning target file: " + target_file)
    let target_bytes = @fs.read_file_to_bytes(target_file)
    let matches = @src.scan_bytes(compiled, target_bytes)

    if matches.length() == 0 {
      println("Verdict: [CLEAN] No malicious signatures found.")
    } else {
      println("Verdict: [ALERT] Malicious signatures found!")
      for m in matches {
        println("  Rule matched: " + m.rule_name)
        for detail in m.matches {
          let (var_name, offset) = detail
          println("    Match: " + var_name + " at offset " + offset.to_string())
        }
      }
    }
  } catch {
    e => println("Error during scanning: " + e.to_string())
  }
}

///|
fn print_usage() -> Unit {
  println("MoonYara CLI — Threat Signature Matching Engine")
  println("Usage:")
  println("  moon run cmd/main -- -r <rules_file> -f <target_file>")
}
