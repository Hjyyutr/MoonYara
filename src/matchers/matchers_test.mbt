///|
test "hex wildcard matching" {
  let pattern = try! parse_hex_pattern("E2 34 ?? 90")
  let data = Bytes::from_array([
    0xE2, 0x34, 0x55, 0x90, 0x00, 0xE2, 0x34, 0xAA, 0x90,
  ])
  let matches = match_hex(pattern, data)
  debug_inspect(matches, content="[0, 5]")
}

///|
test "hex pattern parsing errors" {
  let test_invalid = fn(p : String) {
    try {
      let _ = parse_hex_pattern(p)
      fail("expected parse failure")
    } catch {
      _ => ()
    }
  }
  test_invalid("E2 3")
  test_invalid("E2 G1")
}

///|
test "regex NFA matching basics" {
  let nfa = try! compile_regex("ab*c")
  let data = b"acabcabbc"
  let matches = match_regex(nfa, data)
  debug_inspect(matches, content="[0, 2, 5]")
}

///|
test "regex NFA matching with wildcard" {
  let nfa = try! compile_regex("a.c")
  let data = b"abcaxc"
  let matches = match_regex(nfa, data)
  debug_inspect(matches, content="[0, 3]")
}

///|
test "regex NFA matching alternation and quantifiers" {
  let nfa = try! compile_regex("(abc|def)+")
  let data = b"abcdefabc"
  let matches = match_regex(nfa, data)
  debug_inspect(matches, content="[0, 3, 6]")
}

///|
test "aho-corasick multi-pattern search" {
  let patterns = [b"he", b"she", b"his", b"hers"]
  let ac = AhoCorasick::new(patterns)
  let data = b"ushers"
  let matches = ac.match_aho_corasick(data)
  debug_inspect(matches, content="[(1, 1), (0, 2), (3, 2)]")
}
