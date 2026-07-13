///|
/// AST representation of string matchers in YARA rules.
pub(all) enum YaraString {
  Literal(String, Bytes) // name (e.g. "$a"), content
  Hex(String, Array[@matchers.BytePattern]) // name, hex patterns
  Regex(String, @matchers.Nfa) // name, compiled regular expression
} derive(Eq, Debug)

///|
pub(all) enum CompareOp {
  Eq
  NotEq
  Lt
  LtEq
  Gt
  GtEq
} derive(Eq, Debug)

///|
pub(all) enum YaraExpression {
  FileSize
  IntLiteral(Int)
  Add(YaraExpression, YaraExpression)
  Sub(YaraExpression, YaraExpression)
  Mul(YaraExpression, YaraExpression)
  Div(YaraExpression, YaraExpression)
} derive(Eq, Debug)

///|
/// AST representation of condition expressions in YARA rules.
pub(all) enum YaraCondition {
  True
  False
  StringRef(String) // name (e.g. "$a")
  And(YaraCondition, YaraCondition)
  Or(YaraCondition, YaraCondition)
  Not(YaraCondition)
  Compare(CompareOp, YaraExpression, YaraExpression)
  AnyOfThem
  AllOfThem
  Of(YaraExpression, Array[String])
} derive(Eq, Debug)

///|
/// Complete YARA rule AST.
pub(all) struct YaraRule {
  name : String
  meta : Map[String, String]
  strings : Array[YaraString]
  condition : YaraCondition
} derive(Eq, Debug)
