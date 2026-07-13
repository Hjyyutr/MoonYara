///|
/// Evaluation context containing match status for each string variable.
pub(all) struct MatchContext {
  matched_vars : Map[String, Bool]
  all_vars : Array[String]
  filesize : Int
}

///|
/// Evaluates a YaraExpression using the MatchContext.
pub fn evaluate_expression(expr : YaraExpression, ctx : MatchContext) -> Int {
  match expr {
    FileSize => ctx.filesize
    IntLiteral(val) => val
    Add(left, right) =>
      evaluate_expression(left, ctx) + evaluate_expression(right, ctx)
    Sub(left, right) =>
      evaluate_expression(left, ctx) - evaluate_expression(right, ctx)
    Mul(left, right) =>
      evaluate_expression(left, ctx) * evaluate_expression(right, ctx)
    Div(left, right) => {
      let d = evaluate_expression(right, ctx)
      if d == 0 {
        0
      } else {
        evaluate_expression(left, ctx) / d
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
      match op {
        Eq => l_val == r_val
        NotEq => l_val != r_val
        Lt => l_val < r_val
        LtEq => l_val <= r_val
        Gt => l_val > r_val
        GtEq => l_val >= r_val
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
      let limit = evaluate_expression(expr, ctx)
      let mut count = 0
      for v in list {
        if ctx.matched_vars.get_or_default(v, false) {
          count += 1
        }
      }
      count >= limit
    }
  }
}
