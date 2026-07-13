///|
test "webshell signature detection" {
  let rule_text =
    #|rule WebShellDetect {
    #|  meta:
    #|    description = "Detect simple PHP webshell pattern"
    #|  strings:
    #|    $eval = "eval"
    #|    $get = "$_GET"
    #|    $post = "$_POST"
    #|  condition:
    #|    $eval and ($get or $post)
    #|}

  let compiled = try! compile_rules(rule_text)

  // 1. Positive case (eval and $_GET)
  // Obfuscate to prevent Windows Defender false positive
  let data1 = Bytes::from_array([
    0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, // "<?php "
     0x65, 0x76, 0x61, 0x6c, // "eval"
     0x28, 0x24, 0x5f, 0x47, 0x45, 0x54, // "($_GET"
     0x5b, 0x27, 0x63, 0x6d, 0x64, 0x27, 0x5d, 0x29, 0x3b, 0x20, // "['cmd']); "
     0x3f, 0x3e, // "?>"
  ])
  let matches1 = scan_bytes(compiled, data1)
  debug_inspect(
    matches1.map(fn(m) { m.rule_name }),
    content="[\"WebShellDetect\"]",
  )

  // 2. Negative case (only $_GET, no eval)
  let data2 = Bytes::from_array([
    0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, // "<?php "
     0x65, 0x63, 0x68, 0x6f, 0x20, // "echo "
     0x24, 0x5f, 0x47, 0x45, 0x54, // "$_GET"
     0x5b, 0x27, 0x63, 0x6d, 0x64, 0x27, 0x5d, 0x29, 0x3b, 0x20, // "['cmd']); "
     0x3f, 0x3e, // "?>"
  ])
  let matches2 = scan_bytes(compiled, data2)
  debug_inspect(matches2.map(fn(m) { m.rule_name }), content="[]")
}

///|
test "malware hex and regex detection" {
  let rule_text =
    #|rule MalwareDetect {
    #|  meta:
    #|    description = "Detect malicious hex sequence and regex executions"
    #|  strings:
    #|    $hex = { E2 34 ?? 90 }
    #|    $regex = /exec(ute)?/
    #|  condition:
    #|    $hex or $regex
    #|}

  let compiled = try! compile_rules(rule_text)

  // 1. Matches hex
  let data1 = Bytes::from_array([0x00, 0xE2, 0x34, 0xAA, 0x90, 0x00])
  let matches1 = scan_bytes(compiled, data1)
  debug_inspect(
    matches1.map(fn(m) { m.rule_name }),
    content="[\"MalwareDetect\"]",
  )

  // 2. Matches regex
  let data2 = b"system_execute_process"
  let matches2 = scan_bytes(compiled, data2)
  debug_inspect(
    matches2.map(fn(m) { m.rule_name }),
    content="[\"MalwareDetect\"]",
  )

  // 3. No match
  let data3 = b"hello_world"
  let matches3 = scan_bytes(compiled, data3)
  debug_inspect(matches3.map(fn(m) { m.rule_name }), content="[]")
}

///|
test "filesize conditions" {
  let rule_text =
    #|rule SmallFile {
    #|  condition:
    #|    filesize < 20
    #|}
    #|rule MediumFile {
    #|  condition:
    #|    filesize >= 20 and filesize < 50
    #|}

  let compiled = try! compile_rules(rule_text)

  let data_small = b"hello"
  let matches_small = scan_bytes(compiled, data_small)
  debug_inspect(
    matches_small.map(fn(m) { m.rule_name }),
    content="[\"SmallFile\"]",
  )

  let data_med = b"this is a medium sized payload for testing"
  let matches_med = scan_bytes(compiled, data_med)
  debug_inspect(
    matches_med.map(fn(m) { m.rule_name }),
    content="[\"MediumFile\"]",
  )
}

///|
test "string quantifiers and sets" {
  let rule_text =
    #|rule AnyOfThem {
    #|  strings:
    #|    $a = "apple"
    #|    $b = "banana"
    #|  condition:
    #|    any of them
    #|}
    #|rule AllOfThem {
    #|  strings:
    #|    $a = "apple"
    #|    $b = "banana"
    #|  condition:
    #|    all of them
    #|}
    #|rule SpecificOf {
    #|  strings:
    #|    $a = "apple"
    #|    $b = "banana"
    #|    $c = "cherry"
    #|  condition:
    #|    2 of ($a, $b, $c)
    #|}
    #|rule AnyOfList {
    #|  strings:
    #|    $a = "apple"
    #|    $b = "banana"
    #|  condition:
    #|    any of ($a, $b)
    #|}
    #|rule AllOfList {
    #|  strings:
    #|    $a = "apple"
    #|    $b = "banana"
    #|  condition:
    #|    all of ($a, $b)
    #|}

  let compiled = try! compile_rules(rule_text)

  // 1. One match (apple) -> matches AnyOfThem, AnyOfList
  let data1 = b"an apple tree"
  let matches1 = scan_bytes(compiled, data1)
  debug_inspect(
    matches1.map(fn(m) { m.rule_name }),
    content="[\"AnyOfThem\", \"AnyOfList\"]",
  )

  // 2. Two matches (apple and banana) -> matches all 5 rules
  let data2 = b"apple and banana salad"
  let matches2 = scan_bytes(compiled, data2)
  debug_inspect(
    matches2.map(fn(m) { m.rule_name }),
    content="[\"AnyOfThem\", \"AllOfThem\", \"SpecificOf\", \"AnyOfList\", \"AllOfList\"]",
  )

  // 3. Two matches with cherry (apple and cherry) -> matches AnyOfThem, SpecificOf, AnyOfList
  let data3 = b"cherry and apple pie"
  let matches3 = scan_bytes(compiled, data3)
  debug_inspect(
    matches3.map(fn(m) { m.rule_name }),
    content="[\"AnyOfThem\", \"SpecificOf\", \"AnyOfList\"]",
  )
}
