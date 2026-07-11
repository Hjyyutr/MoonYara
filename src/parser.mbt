///| Private parser struct.
priv struct Parser {
  input : Array[Char]
  mut pos : Int
}

fn Parser::new(input : String) -> Parser {
  Parser::{ input: input.to_array(), pos: 0 }
}

fn Parser::expect(self : Parser, tok : String) -> Bool {
  self.skip_whitespace()
  let tok_chars = tok.to_array()
  if self.pos + tok_chars.length() > self.input.length() {
    return false
  }
  for i in 0..<tok_chars.length() {
    if self.input[self.pos + i] != tok_chars[i] {
      return false
    }
  }
  self.pos += tok_chars.length()
  true
}

fn Parser::skip_whitespace(self : Parser) -> Unit {
  while self.pos < self.input.length() {
    let c = self.input[self.pos]
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
      self.pos += 1
    } else if c == '/' && self.pos + 1 < self.input.length() && self.input[self.pos + 1] == '/' {
      self.pos += 2
      while self.pos < self.input.length() && self.input[self.pos] != '\n' {
        self.pos += 1
      }
    } else {
      break
    }
  }
}

fn Parser::parse_ident(self : Parser) -> String raise @matchers.YaraError {
  let start = self.pos
  while self.pos < self.input.length() {
    let c = self.input[self.pos]
    if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
      self.pos += 1
    } else {
      break
    }
  }
  if self.pos == start {
    raise @matchers.YaraError::ValueError("Expected identifier at index " + start.to_string())
  }
  let chars = self.input[start:self.pos]
  String::from_array(chars.to_owned())
}

fn Parser::peek_word(self : Parser) -> String {
  let saved = self.pos
  self.skip_whitespace()
  let start = self.pos
  while self.pos < self.input.length() {
    let c = self.input[self.pos]
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '{' || c == '}' || c == '(' || c == ')' || c == '=' || c == ':' || c == ';' {
      break
    }
    self.pos += 1
  }
  let word_chars = self.input[start:self.pos]
  let word = String::from_array(word_chars.to_owned())
  self.pos = saved
  word
}

fn Parser::parse_string_literal(self : Parser) -> String raise @matchers.YaraError {
  if self.pos >= self.input.length() || self.input[self.pos] != '"' {
    raise @matchers.YaraError::ValueError("Expected string literal starting with '\"'")
  }
  self.pos += 1
  let start = self.pos
  while self.pos < self.input.length() && self.input[self.pos] != '"' {
    self.pos += 1
  }
  if self.pos >= self.input.length() {
    raise @matchers.YaraError::ValueError("Unterminated string literal")
  }
  let s_chars = self.input[start:self.pos]
  let s = String::from_array(s_chars.to_owned())
  self.pos += 1
  s
}

fn Parser::parse_braced_hex(self : Parser) -> String raise @matchers.YaraError {
  if self.pos >= self.input.length() || self.input[self.pos] != '{' {
    raise @matchers.YaraError::ValueError("Expected hex pattern starting with '{'")
  }
  self.pos += 1
  let start = self.pos
  while self.pos < self.input.length() && self.input[self.pos] != '}' {
    self.pos += 1
  }
  if self.pos >= self.input.length() {
    raise @matchers.YaraError::ValueError("Unterminated hex pattern")
  }
  let h_chars = self.input[start:self.pos]
  let h = String::from_array(h_chars.to_owned())
  self.pos += 1
  h
}

fn Parser::parse_slashed_regex(self : Parser) -> String raise @matchers.YaraError {
  if self.pos >= self.input.length() || self.input[self.pos] != '/' {
    raise @matchers.YaraError::ValueError("Expected regular expression starting with '/'")
  }
  self.pos += 1
  let start = self.pos
  while self.pos < self.input.length() && self.input[self.pos] != '/' {
    self.pos += 1
  }
  if self.pos >= self.input.length() {
    raise @matchers.YaraError::ValueError("Unterminated regular expression")
  }
  let r_chars = self.input[start:self.pos]
  let r = String::from_array(r_chars.to_owned())
  self.pos += 1
  r
}

fn Parser::parse_meta_block(self : Parser, meta : Map[String, String]) -> Unit raise @matchers.YaraError {
  self.skip_whitespace()
  while self.pos < self.input.length() {
    let next_word = self.peek_word()
    if next_word == "strings" || next_word == "condition" || next_word == "}" {
      break
    }
    let key = self.parse_ident()
    self.skip_whitespace()
    if !self.expect("=") {
      raise @matchers.YaraError::ValueError("Expected '=' after meta key")
    }
    self.skip_whitespace()
    let val = self.parse_string_literal()
    meta.set(key, val)
    self.skip_whitespace()
  }
}

fn Parser::parse_strings_block(self : Parser) -> Array[YaraString] raise @matchers.YaraError {
  let strings = []
  self.skip_whitespace()
  while self.pos < self.input.length() {
    let next_word = self.peek_word()
    if next_word == "condition" || next_word == "}" {
      break
    }
    if !self.expect("$") {
      raise @matchers.YaraError::ValueError("Expected YARA string variable identifier starting with '$'")
    }
    let var_name = "$" + self.parse_ident()
    self.skip_whitespace()
    if !self.expect("=") {
      raise @matchers.YaraError::ValueError("Expected '=' after string variable name")
    }
    self.skip_whitespace()
    if self.pos < self.input.length() && self.input[self.pos] == '"' {
      let literal = self.parse_string_literal()
      let bytes = Bytes::from_array(literal.to_array().map(fn(c) { c.to_int().to_byte() }))
      strings.push(YaraString::Literal(var_name, bytes))
    } else if self.pos < self.input.length() && self.input[self.pos] == '{' {
      let hex_str = self.parse_braced_hex()
      let hex_pattern = @matchers.parse_hex_pattern(hex_str)
      strings.push(YaraString::Hex(var_name, hex_pattern))
    } else if self.pos < self.input.length() && self.input[self.pos] == '/' {
      let regex_str = self.parse_slashed_regex()
      let nfa = @matchers.compile_regex(regex_str)
      strings.push(YaraString::Regex(var_name, nfa))
    } else {
      raise @matchers.YaraError::ValueError("Unsupported pattern type for string: " + var_name)
    }
    self.skip_whitespace()
  }
  strings
}

fn Parser::parse_cond_atom(self : Parser) -> YaraCondition raise @matchers.YaraError {
  self.skip_whitespace()
  if self.expect("(") {
    let node = self.parse_cond_or()
    self.skip_whitespace()
    if !self.expect(")") {
      raise @matchers.YaraError::ValueError("Expected ')' in condition expression")
    }
    node
  } else if self.expect("true") {
    YaraCondition::True
  } else if self.expect("false") {
    YaraCondition::False
  } else if self.expect("$") {
    let name = "$" + self.parse_ident()
    YaraCondition::StringRef(name)
  } else {
    let next = self.peek_word()
    raise @matchers.YaraError::ValueError("Expected term in condition, found: " + next)
  }
}

fn Parser::parse_cond_not(self : Parser) -> YaraCondition raise @matchers.YaraError {
  self.skip_whitespace()
  if self.expect("not") {
    let child = self.parse_cond_not()
    YaraCondition::Not(child)
  } else {
    self.parse_cond_atom()
  }
}

fn Parser::parse_cond_and(self : Parser) -> YaraCondition raise @matchers.YaraError {
  let mut node = self.parse_cond_not()
  self.skip_whitespace()
  while self.expect("and") {
    let right = self.parse_cond_not()
    node = YaraCondition::And(node, right)
    self.skip_whitespace()
  }
  node
}

fn Parser::parse_cond_or(self : Parser) -> YaraCondition raise @matchers.YaraError {
  let mut node = self.parse_cond_and()
  self.skip_whitespace()
  while self.expect("or") {
    let right = self.parse_cond_and()
    node = YaraCondition::Or(node, right)
    self.skip_whitespace()
  }
  node
}

fn Parser::parse_condition(self : Parser) -> YaraCondition raise @matchers.YaraError {
  self.parse_cond_or()
}

fn Parser::parse_rule(self : Parser) -> YaraRule raise @matchers.YaraError {
  self.skip_whitespace()
  if !self.expect("rule") {
    raise @matchers.YaraError::ValueError("Expected 'rule' keyword")
  }
  self.skip_whitespace()
  let name = self.parse_ident()
  self.skip_whitespace()
  if !self.expect("{") {
    raise @matchers.YaraError::ValueError("Expected '{' to open rule body")
  }
  
  let meta = Map([])
  let mut strings = []
  let mut condition = YaraCondition::True
  
  self.skip_whitespace()
  while self.pos < self.input.length() {
    if self.expect("}") {
      break
    }
    if self.expect("meta:") {
      self.parse_meta_block(meta)
    } else if self.expect("strings:") {
      strings = self.parse_strings_block()
    } else if self.expect("condition:") {
      condition = self.parse_condition()
    } else {
      let next = self.peek_word()
      raise @matchers.YaraError::ValueError("Unexpected token in rule structure: " + next)
    }
    self.skip_whitespace()
  }
  
  YaraRule::{ name, meta, strings, condition }
}

///| Top-level function to parse YARA rules text.
pub fn parse_rules(rules_text : String) -> Array[YaraRule] raise @matchers.YaraError {
  let parser = Parser::new(rules_text)
  let rules = []
  parser.skip_whitespace()
  while parser.pos < parser.input.length() {
    let r = parser.parse_rule()
    rules.push(r)
    parser.skip_whitespace()
  }
  rules
}
