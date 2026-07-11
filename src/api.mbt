///|
/// Compilation result holding multiple compiled rules.
pub(all) struct CompiledRules {
  rules : Array[CompiledRule]
} derive(Eq, Debug)

///|
/// Parses and compiles YARA rules text.
pub fn compile_rules(
  rules_text : String,
) -> CompiledRules raise @matchers.YaraError {
  let parsed = parse_rules(rules_text)
  let compiled = parsed.map(compile_rule)
  CompiledRules::{ rules: compiled }
}

///|
/// Single match result detailing a matched rule and its matching string variable offsets.
pub(all) struct YaraMatch {
  rule_name : String
  matches : Array[(String, Int)] // variable name, match offset
} derive(Eq, Debug)

///|
/// Scans data bytes against compiled rules.
pub fn scan_bytes(compiled : CompiledRules, data : Bytes) -> Array[YaraMatch] {
  let results = []
  for rule in compiled.rules {
    let matched_vars = Map([])
    let detail_matches = []

    // 1. Literal matching via Aho-Corasick
    if rule.literals.length() > 0 {
      let literal_bytes = rule.literals.map(fn(pair) { pair.1 })
      let ac = @matchers.AhoCorasick::new(literal_bytes)
      let ac_matches = ac.match_aho_corasick(data)
      for m in ac_matches {
        let (pattern_id, offset) = m
        let var_name = rule.literals[pattern_id].0
        matched_vars.set(var_name, true)
        detail_matches.push((var_name, offset))
      }
    }

    // 2. Hex matching
    for hex_pair in rule.hex_patterns {
      let (var_name, pattern) = hex_pair
      let matches = @matchers.match_hex(pattern, data)
      if matches.length() > 0 {
        matched_vars.set(var_name, true)
        for offset in matches {
          detail_matches.push((var_name, offset))
        }
      }
    }

    // 3. Regular expression matching
    for regex_pair in rule.regex_patterns {
      let (var_name, nfa) = regex_pair
      let matches = @matchers.match_regex(nfa, data)
      if matches.length() > 0 {
        matched_vars.set(var_name, true)
        for offset in matches {
          detail_matches.push((var_name, offset))
        }
      }
    }

    // 4. Condition evaluation
    let ctx = MatchContext::{ matched_vars, }
    if evaluate_condition(rule.condition, ctx) {
      results.push(YaraMatch::{ rule_name: rule.name, matches: detail_matches })
    }
  }
  results
}
