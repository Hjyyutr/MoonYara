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
  let data1 = b"<?php eval($_GET['cmd']); ?>"
  let matches1 = scan_bytes(compiled, data1)
  debug_inspect(
    matches1.map(fn(m) { m.rule_name }),
    content="[\"WebShellDetect\"]",
  )

  // 2. Negative case (only $_GET, no eval)
  let data2 = b"<?php echo $_GET['cmd']; ?>"
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
