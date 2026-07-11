///| AST representing a regular expression.
pub(all) enum RegexAST {
  Empty
  Char(Char)
  Any
  Concat(RegexAST, RegexAST)
  Alter(RegexAST, RegexAST)
  Star(RegexAST)
  Plus(RegexAST)
  Question(RegexAST)
} derive(Eq, Debug)

///| Parser state for converting regex strings into RegexAST.
priv struct RegexParser {
  input : Array[Char]
  mut pos : Int
}

fn RegexParser::new(pattern : String) -> RegexParser {
  RegexParser::{ input: pattern.to_array(), pos: 0 }
}

fn RegexParser::parse_alter(self : RegexParser) -> RegexAST raise YaraError {
  let mut node = self.parse_concat()
  while self.pos < self.input.length() && self.input[self.pos] == '|' {
    self.pos += 1
    let right = self.parse_concat()
    node = RegexAST::Alter(node, right)
  }
  node
}

fn RegexParser::parse_concat(self : RegexParser) -> RegexAST raise YaraError {
  let mut node = RegexAST::Empty
  while self.pos < self.input.length() {
    let next_char = self.input[self.pos]
    if next_char == '|' || next_char == ')' {
      break
    }
    let factor = self.parse_factor()
    if node is RegexAST::Empty {
      node = factor
    } else {
      node = RegexAST::Concat(node, factor)
    }
  }
  node
}

fn RegexParser::parse_factor(self : RegexParser) -> RegexAST raise YaraError {
  let mut node = self.parse_atom()
  if self.pos < self.input.length() {
    let next_char = self.input[self.pos]
    if next_char == '*' {
      self.pos += 1
      node = RegexAST::Star(node)
    } else if next_char == '+' {
      self.pos += 1
      node = RegexAST::Plus(node)
    } else if next_char == '?' {
      self.pos += 1
      node = RegexAST::Question(node)
    }
  }
  node
}

fn RegexParser::parse_atom(self : RegexParser) -> RegexAST raise YaraError {
  if self.pos >= self.input.length() {
    raise YaraError::ValueError("Unexpected end of regex pattern")
  }
  let c = self.input[self.pos]
  if c == '(' {
    self.pos += 1
    let node = self.parse_alter()
    if self.pos >= self.input.length() || self.input[self.pos] != ')' {
      raise YaraError::ValueError("Unmatched parenthesis in regex")
    }
    self.pos += 1
    node
  } else if c == '.' {
    self.pos += 1
    RegexAST::Any
  } else if c == '\\' {
    self.pos += 1
    if self.pos >= self.input.length() {
      raise YaraError::ValueError("Trailing backslash in regex")
    }
    let esc = self.input[self.pos]
    self.pos += 1
    RegexAST::Char(esc)
  } else if c == '*' || c == '+' || c == '?' || c == '|' || c == ')' {
    raise YaraError::ValueError("Unexpected special character in regex: " + c.to_string())
  } else {
    self.pos += 1
    RegexAST::Char(c)
  }
}

///| Parses a regular expression string into AST.
pub fn parse_regex_ast(pattern : String) -> RegexAST raise YaraError {
  let parser = RegexParser::new(pattern)
  let ast = parser.parse_alter()
  if parser.pos < parser.input.length() {
    raise YaraError::ValueError("Unexpected character in regex at index " + parser.pos.to_string())
  }
  ast
}

///| NFA execution state operations.
pub(all) enum NfaOp {
  Match
  Char(Char, Int)
  Any(Int)
  Split(Int, Int)
} derive(Eq, Debug)

///| A single state in the NFA.
pub(all) struct NfaState {
  id : Int
  op : NfaOp
} derive(Eq, Debug)

///| Compiled NFA regex matcher.
pub(all) struct Nfa {
  states : Array[NfaState]
  start : Int
}

priv struct NfaBuilder {
  states : Array[NfaState]
}

fn NfaBuilder::add_state(self : NfaBuilder, op : NfaOp) -> Int {
  let id = self.states.length()
  self.states.push(NfaState::{ id, op })
  id
}

fn NfaBuilder::compile(self : NfaBuilder, ast : RegexAST, next : Int) -> Int {
  match ast {
    Empty => next
    Char(c) => self.add_state(NfaOp::Char(c, next))
    Any => self.add_state(NfaOp::Any(next))
    Concat(left, right) => {
      let right_entry = self.compile(right, next)
      self.compile(left, right_entry)
    }
    Alter(left, right) => {
      let left_entry = self.compile(left, next)
      let right_entry = self.compile(right, next)
      self.add_state(NfaOp::Split(left_entry, right_entry))
    }
    Star(node) => {
      let split_id = self.add_state(NfaOp::Split(0, next)) // placeholder
      let node_entry = self.compile(node, split_id)
      self.states[split_id] = NfaState::{ id: split_id, op: NfaOp::Split(node_entry, next) }
      split_id
    }
    Plus(node) => {
      let split_id = self.add_state(NfaOp::Split(0, next)) // placeholder
      let node_entry = self.compile(node, split_id)
      self.states[split_id] = NfaState::{ id: split_id, op: NfaOp::Split(node_entry, next) }
      node_entry
    }
    Question(node) => {
      let node_entry = self.compile(node, next)
      self.add_state(NfaOp::Split(node_entry, next))
    }
  }
}

///| Compiles a regular expression string into NFA.
pub fn compile_regex(pattern : String) -> Nfa raise YaraError {
  let ast = parse_regex_ast(pattern)
  let builder = NfaBuilder::{ states: [] }
  let match_id = builder.add_state(NfaOp::Match)
  let start = builder.compile(ast, match_id)
  Nfa::{ states: builder.states, start }
}

priv struct NfaRunner {
  states : Array[NfaState]
  active : Array[Int]
  visited : Array[Bool]
}

fn NfaRunner::new(states : Array[NfaState]) -> NfaRunner {
  NfaRunner::{
    states,
    active: [],
    visited: Array::make(states.length(), false),
  }
}

fn NfaRunner::add_active(self : NfaRunner, id : Int) -> Unit {
  if self.visited[id] {
    return
  }
  self.visited[id] = true
  match self.states[id].op {
    Split(s1, s2) => {
      self.add_active(s1)
      self.add_active(s2)
    }
    _ => self.active.push(id)
  }
}

///| Runs regex matching on a byte stream.
/// Returns start positions where the pattern matches.
pub fn match_regex(nfa : Nfa, data : Bytes) -> Array[Int] {
  let matches = []
  let match_state_id = nfa.states.length() - 1 // The Match state index
  
  for start_pos in 0..=data.length() {
    let runner = NfaRunner::new(nfa.states)
    runner.add_active(nfa.start)
    
    if runner.active.contains(match_state_id) {
      matches.push(start_pos)
      continue
    }
    
    let mut pos = start_pos
    let mut is_matched = false
    let mut current_runner = runner
    while pos < data.length() && current_runner.active.length() > 0 {
      let b = data[pos]
      let next_runner = NfaRunner::new(nfa.states)
      for state_id in current_runner.active {
        match nfa.states[state_id].op {
          Char(expected, next) => {
            let expected_b = expected.to_int().to_byte()
            if expected_b == b {
              next_runner.add_active(next)
            }
          }
          Any(next) => {
            next_runner.add_active(next)
          }
          _ => ()
        }
      }
      current_runner = next_runner
      if current_runner.active.contains(match_state_id) {
        is_matched = true
        break
      }
      pos += 1
    }
    if is_matched {
      matches.push(start_pos)
    }
  }
  matches
}
