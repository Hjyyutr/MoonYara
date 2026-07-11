///|
/// Compiled representation of a YARA rule.
pub(all) struct CompiledRule {
  name : String
  meta : Map[String, String]
  literals : Array[(String, Bytes)]
  hex_patterns : Array[(String, Array[@matchers.BytePattern])]
  regex_patterns : Array[(String, @matchers.Nfa)]
  condition : YaraCondition
} derive(Eq, Debug)

///|
/// Compiles a parsed YARA rule into CompiledRule.
pub fn compile_rule(rule : YaraRule) -> CompiledRule {
  let literals = []
  let hex_patterns = []
  let regex_patterns = []
  for s in rule.strings {
    match s {
      Literal(name, bytes) => literals.push((name, bytes))
      Hex(name, pattern) => hex_patterns.push((name, pattern))
      Regex(name, nfa) => regex_patterns.push((name, nfa))
    }
  }
  CompiledRule::{
    name: rule.name,
    meta: rule.meta,
    literals,
    hex_patterns,
    regex_patterns,
    condition: rule.condition,
  }
}
