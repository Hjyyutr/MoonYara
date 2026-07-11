///| Evaluation context containing match status for each string variable.
pub(all) struct MatchContext {
  matched_vars : Map[String, Bool]
}

///| Evaluates a YaraCondition using the MatchContext.
pub fn evaluate_condition(cond : YaraCondition, ctx : MatchContext) -> Bool {
  match cond {
    True => true
    False => false
    StringRef(name) => ctx.matched_vars.get_or_default(name, false)
    And(left, right) => evaluate_condition(left, ctx) && evaluate_condition(right, ctx)
    Or(left, right) => evaluate_condition(left, ctx) || evaluate_condition(right, ctx)
    Not(child) => !evaluate_condition(child, ctx)
  }
}
