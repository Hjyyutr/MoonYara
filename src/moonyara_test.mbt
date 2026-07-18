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

///|

///|

///|

///|
test "pe module scanning" {
  let rule_text =
    #|import "pe"
    #|rule PETest {
    #|  condition:
    #|    pe.entry_point == 4096 and pe.number_of_sections == 4 and pe.machine == 332
    #|}

  let compiled = try! compile_rules(rule_text)

  // Construct mock PE file in mutable array
  let data = Array::make(256, (0).to_byte())
  // MZ
  data[0] = (0x4d).to_byte()
  data[1] = (0x5a).to_byte()
  // PE offset at 0x3c: 64 (0x40)
  data[0x3c] = (0x40).to_byte()
  // PE signature at 0x40
  data[0x40] = (0x50).to_byte()
  data[0x41] = (0x45).to_byte()
  // COFF Header
  // Machine: 0x14c (332)
  data[0x44] = (0x4c).to_byte()
  data[0x45] = (0x01).to_byte()
  // Number of sections: 4
  data[0x46] = (0x04).to_byte()
  // Size of Optional Header: 96
  data[0x54] = (96).to_byte()
  // Optional Header (PE32)
  // Magic: 0x10b
  data[0x58] = (0x0b).to_byte()
  data[0x59] = (0x01).to_byte()
  // AddressOfEntryPoint: 0x1000 (4096)
  data[0x68] = (0x00).to_byte()
  data[0x69] = (0x10).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"PETest\"]")
}

///|
test "elf module scanning" {
  let rule_text =
    #|import "elf"
    #|rule ELFTest {
    #|  condition:
    #|    elf.entry_point == 134512640 and elf.machine == 3 and elf.type == 2
    #|}

  let compiled = try! compile_rules(rule_text)

  // Construct mock ELF32 file in mutable array
  let data = Array::make(128, (0).to_byte())
  // \x7fELF
  data[0] = (0x7f).to_byte()
  data[1] = (0x45).to_byte()
  data[2] = (0x4c).to_byte()
  data[3] = (0x46).to_byte()
  // Class: 1 (32-bit)
  data[4] = (1).to_byte()
  // Encoding: 1 (little-endian)
  data[5] = (1).to_byte()
  // Version: 1
  data[6] = (1).to_byte()
  // Type: 2 (executable)
  data[16] = (2).to_byte()
  // Machine: 3 (Intel 386)
  data[18] = (3).to_byte()
  // Entry point: 0x8048000 (134512640)
  data[24] = (0x00).to_byte()
  data[25] = (0x80).to_byte()
  data[26] = (0x04).to_byte()
  data[27] = (0x08).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"ELFTest\"]")
}

///|
test "macho module scanning" {
  let rule_text =
    #|import "macho"
    #|rule MachOTest {
    #|  condition:
    #|    macho.cputype == 7 and macho.filetype == 2
    #|}

  let compiled = try! compile_rules(rule_text)

  // Construct mock Mach-O file in mutable array
  let data = Array::make(64, (0).to_byte())
  // magic: 0xfeedface
  data[0] = (0xfe).to_byte()
  data[1] = (0xed).to_byte()
  data[2] = (0xfa).to_byte()
  data[3] = (0xce).to_byte()
  // cputype: 7
  data[7] = (7).to_byte()
  // filetype: 2
  data[15] = (2).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"MachOTest\"]")
}

///|
test "zip module scanning" {
  let rule_text =
    #|import "zip"
    #|rule ZipTest {
    #|  condition:
    #|    zip.number_of_files == 1
    #|}

  let compiled = try! compile_rules(rule_text)

  // Construct mock ZIP file in mutable array
  let data = Array::make(64, (0).to_byte())
  // PK\x03\x04
  data[0] = (0x50).to_byte()
  data[1] = (0x4b).to_byte()
  data[2] = (0x03).to_byte()
  data[3] = (0x04).to_byte()
  // filename_len: 8
  data[26] = (8).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"ZipTest\"]")
}

///|
test "pe section scanning" {
  let rule_text =
    #|import "pe"
    #|rule PESecTest {
    #|  condition:
    #|    pe.sections[0].name == ".text" and pe.sections[0].virtual_address == 4096
    #|}

  let compiled = try! compile_rules(rule_text)

  let data = Array::make(512, (0).to_byte())
  // MZ
  data[0] = (0x4d).to_byte()
  data[1] = (0x5a).to_byte()
  // PE offset at 0x3c: 64 (0x40)
  data[0x3c] = (0x40).to_byte()
  // PE signature at 0x40
  data[0x40] = (0x50).to_byte()
  data[0x41] = (0x45).to_byte()
  // COFF Header: Machine=332, NumberOfSections=1
  data[0x44] = (0x4c).to_byte()
  data[0x45] = (0x01).to_byte()
  data[0x46] = (0x01).to_byte()
  // SizeOfOptionalHeader: 96
  data[0x54] = (96).to_byte()
  // Optional Header magic: 0x10b
  data[0x58] = (0x0b).to_byte()
  data[0x59] = (0x01).to_byte()

  // Sections start at opt_header_start (64 + 24 = 88) + SizeOfOptionalHeader (96) = 184
  // Section name: ".text"
  data[184] = '.'.to_int().to_byte()
  data[185] = 't'.to_int().to_byte()
  data[186] = 'e'.to_int().to_byte()
  data[187] = 'x'.to_int().to_byte()
  data[188] = 't'.to_int().to_byte()
  // virtual size at 184 + 8: 1000 (0x3e8)
  data[192] = (0xe8).to_byte()
  data[193] = (0x03).to_byte()
  // virtual address at 184 + 12: 4096 (0x1000)
  data[196] = (0x00).to_byte()
  data[197] = (0x10).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"PESecTest\"]")
}

///|
test "elf section scanning" {
  let rule_text =
    #|import "elf"
    #|rule ELFSecTest {
    #|  condition:
    #|    elf.sections[0].size == 1234 and elf.sections[0].type == 1
    #|}

  let compiled = try! compile_rules(rule_text)

  let data = Array::make(256, (0).to_byte())
  // \x7fELF
  data[0] = (0x7f).to_byte()
  data[1] = (0x45).to_byte()
  data[2] = (0x4c).to_byte()
  data[3] = (0x46).to_byte()
  // Class: 1 (32-bit), Encoding: 1 (little-endian)
  data[4] = (1).to_byte()
  data[5] = (1).to_byte()
  // sh_off (Section Header Table Offset) at 32 (32-bit): 64 (0x40)
  data[32] = (0x40).to_byte()
  // sh_ent_size at 46 (16-bit): 40
  data[46] = (40).to_byte()
  // sh_num (Number of Section Headers) at 48 (16-bit): 1
  data[48] = (1).to_byte()

  // Section 0 at 64
  // type (offset 4): 1
  data[68] = (1).to_byte()
  // size (offset 20): 1234 (0x000004d2)
  data[84] = (0xd2).to_byte()
  data[85] = (0x04).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"ELFSecTest\"]")
}

///|
test "macho segment scanning" {
  let rule_text =
    #|import "macho"
    #|rule MachOSegTest {
    #|  condition:
    #|    macho.segments[0].segname == "__TEXT" and macho.segments[0].filesize == 1024
    #|}

  let compiled = try! compile_rules(rule_text)

  let data = Array::make(128, (0).to_byte())
  // magic: 0xfeedface
  data[0] = (0xfe).to_byte()
  data[1] = (0xed).to_byte()
  data[2] = (0xfa).to_byte()
  data[3] = (0xce).to_byte()
  // cputype: 7
  data[7] = (7).to_byte()
  // ncmds: 1 (offset 16, big-endian)
  data[19] = (1).to_byte()
  // sizeofcmds: 56 (offset 20)
  data[23] = (56).to_byte()

  // Load Command starts at 28
  // cmd: LC_SEGMENT (1)
  data[31] = (1).to_byte()
  // cmdsize: 56
  data[35] = (56).to_byte()
  // segname: "__TEXT"
  data[36] = '_'.to_int().to_byte()
  data[37] = '_'.to_int().to_byte()
  data[38] = 'T'.to_int().to_byte()
  data[39] = 'E'.to_int().to_byte()
  data[40] = 'X'.to_int().to_byte()
  data[41] = 'T'.to_int().to_byte()
  // filesize starts at 36 + 8 + 8 + 12 = 64 (big-endian: 1024 = 0x0400)
  data[66] = (4).to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"MachOSegTest\"]",
  )
}

///|
test "zip file list scanning" {
  let rule_text =
    #|import "zip"
    #|rule ZipFileTest {
    #|  condition:
    #|    zip.files[0].filename == "a.txt" and zip.files[0].uncompressed_size == 20
    #|}

  let compiled = try! compile_rules(rule_text)

  let data = Array::make(128, (0).to_byte())
  // PK\x03\x04
  data[0] = (0x50).to_byte()
  data[1] = (0x4b).to_byte()
  data[2] = (0x03).to_byte()
  data[3] = (0x04).to_byte()
  // uncompressed_size (offset 22): 20
  data[22] = (20).to_byte()
  // filename_len (offset 26): 5
  data[26] = (5).to_byte()
  // filename: "a.txt"
  data[30] = 'a'.to_int().to_byte()
  data[31] = '.'.to_int().to_byte()
  data[32] = 't'.to_int().to_byte()
  data[33] = 'x'.to_int().to_byte()
  data[34] = 't'.to_int().to_byte()

  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"ZipFileTest\"]")
}

///|
test "math and hash scanning" {
  let rule_text =
    #|import "math"
    #|import "hash"
    #|rule MathHashTest {
    #|  condition:
    #|    math.entropy(0, filesize) == 158 and
    #|    math.mean(0, filesize) == 98 and
    #|    hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72"
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"abc"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"MathHashTest\"]",
  )
}

///|
test "base64 and crc32 scanning" {
  let rule_text =
    #|import "hash"
    #|rule Base64Crc32Test {
    #|  condition:
    #|    hash.base64(0, filesize) == "YWJj" and
    #|    hash.crc32(0, filesize) == 891568578
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"abc"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"Base64Crc32Test\"]",
  )
}

///|
test "base64 decode scanning" {
  let rule_text =
    #|import "hash"
    #|rule Base64DecodeTest {
    #|  condition:
    #|    hash.base64_decode("YWJj") == "abc"
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"abc"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"Base64DecodeTest\"]",
  )
}

///|
test "nested math expression scanning" {
  let rule_text =
    #|import "math"
    #|rule NestedMathTest {
    #|  condition:
    #|    (math.entropy(0, filesize) * 2) - 100 == 216
    #|}

  let compiled = compile_rules(rule_text) catch {
    ValueError(msg) => {
      println("COMPILE ERROR: \{msg}")
      fail("nested math failed: \{msg}")
    }
  }
  let bytes = b"abc"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"NestedMathTest\"]",
  )
}

///|
test "math standard deviation scanning" {
  let rule_text =
    #|import "math"
    #|rule DevTest {
    #|  condition:
    #|    math.deviation(0, filesize, 98) == 0
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"bbb"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[\"DevTest\"]")
}

///|
test "truncated file parsing safety" {
  let pe_empty = parse_pe(b"")
  debug_inspect(pe_empty.is_pe, content="false")
  let elf_empty = parse_elf(b"")
  debug_inspect(elf_empty.is_elf, content="false")
  let macho_empty = parse_macho(b"")
  debug_inspect(macho_empty.is_macho, content="false")
  let zip_empty = parse_zip(b"")
  debug_inspect(zip_empty.is_zip, content="false")
}

///|
test "complex boolean condition combination scanning" {
  let rule_text =
    #|import "pe"
    #|import "math"
    #|rule ComplexComboTest {
    #|  condition:
    #|    (pe.entry_point == 0 or pe.entry_point == 4096) and
    #|    not (math.mean(0, filesize) == 0) and
    #|    (math.entropy(0, filesize) > 100 or filesize == 0)
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"abc"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"ComplexComboTest\"]",
  )
}

///|
test "crc32 and entropy standard test vectors" {
  let rule_text =
    #|import "math"
    #|import "hash"
    #|rule StandardVectorsTest {
    #|  condition:
    #|    math.entropy(0, filesize) == 316 and
    #|    hash.crc32(0, filesize) == 0 - 873187034
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"123456789"
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(
    matches.map(fn(m) { m.rule_name }),
    content="[\"StandardVectorsTest\"]",
  )
}

///|
test "pe section out of bounds scanning safety" {
  let rule_text =
    #|import "pe"
    #|rule PESecOOBTest {
    #|  condition:
    #|    pe.sections[99].name == ""
    #|}

  let compiled = try! compile_rules(rule_text)
  let data = Array::make(256, (0).to_byte())
  data[0] = (0x4d).to_byte()
  data[1] = (0x5a).to_byte()
  let bytes = Bytes::from_array(data)
  let matches = scan_bytes(compiled, bytes)
  debug_inspect(matches.map(fn(m) { m.rule_name }), content="[]")
}

///|
test "multiple rules compilation and scanning" {
  let rule_text =
    #|rule FirstRule {
    #|  strings:
    #|    $a = "hello"
    #|  condition:
    #|    $a
    #|}
    #|rule SecondRule {
    #|  strings:
    #|    $b = "world"
    #|  condition:
    #|    $b
    #|}

  let compiled = try! compile_rules(rule_text)
  let bytes = b"hello test world"
  let matches = scan_bytes(compiled, bytes)
  let matched_names = matches.map(fn(m) { m.rule_name })
  debug_inspect(matched_names, content="[\"FirstRule\", \"SecondRule\"]")
}

///|
test "abnormal and invalid rule syntax handling" {
  // Test case 1: Mismatched parentheses in condition block
  let invalid_parens =
    #|rule InvalidMismatchedParens {
    #|  condition:
    #|    ( 1 + 2
    #|}
  let res1 = try {
    let _ = compile_rules(invalid_parens)
    false
  } catch {
    _ => true
  }
  inspect(res1, content="true")

  // Test case 2: Missing rule name
  let missing_name =
    #|rule {
    #|  condition:
    #|    true
    #|}
  let res2 = try {
    let _ = compile_rules(missing_name)
    false
  } catch {
    _ => true
  }
  inspect(res2, content="true")

  // Test case 3: Invalid token/keyword inside condition block
  let unknown_token =
    #|rule UnknownToken {
    #|  condition:
    #|    some_invalid_token_xyz
    #|}
  let res3 = try {
    let _ = compile_rules(unknown_token)
    false
  } catch {
    _ => true
  }
  inspect(res3, content="true")

  // Test case 4: Unclosed string literal in string declaration
  let unclosed_str =
    #|rule UnclosedString {
    #|  strings:
    #|    $a = "hello
    #|  condition:
    #|    $a
    #|}
  let res4 = try {
    let _ = compile_rules(unclosed_str)
    false
  } catch {
    _ => true
  }
  inspect(res4, content="true")
}

