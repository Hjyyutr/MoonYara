# 🌕 MoonYara — 威胁特征匹配与恶意代码扫描引擎

MoonYara 是一个完全使用 **MoonBit** 语言原生开发的轻量级、高性能威胁特征匹配与恶意代码检测引擎（对标经典的 YARA 工具）。

该项目 100% 纯 MoonBit 实现，**零外部 FFI 依赖 (Zero-FFI)**，可编译为 WebAssembly、JavaScript 以及 Native 目标。
其核心价值在于支持在用户上传文件前，直接在浏览器端或边缘沙箱内运行 **Wasm 离线扫描**，有效阻断 Webshell、木马及恶意文件的上传，降低服务器防御开销。

---

## ✨ 核心特性

1. **Aho-Corasick 多模式匹配**：在单次线性扫描中，同时检索所有规则中的多个明文字符串模式，极大地提升了多特征匹配效率。
2. **Thompson NFA 正则引擎**：自主开发并实现了一个抗 **ReDoS (正则拒绝服务攻击)** 的 Thompson NFA 正则引擎，确保在解析恶意特征的复杂正则时，拥有稳定的 $O(M \times N)$ 运行时间。
3. **Hex 通配符匹配**：支持 YARA 格式的十六进制通配符序列解析与高速位匹配（例如：`{ E2 34 ?? 90 }`）。
4. **YARA 兼容编译器与条件 VM**：支持解析标准的 YARA 规则结构（含 `meta` 元数据、`strings` 声明、`condition` 逻辑表达式），并在扫描时以轻量级布尔虚拟机评估匹配结果。

---

## 📦 架构设计

```
                                  +-----------------------+
                                  |   YARA Rule (String)  |
                                  +-----------+-----------+
                                              |
                                              v [Parser]
                                  +-----------+-----------+
                                  |        Rule AST       |
                                  +-----------+-----------+
                                              |
                                              v [Compiler]
                                  +-----------+-----------+
                    +-------------+     Compiled Rules    +-------------+
                    |             +-----------+-----------+             |
                    |                         |                         |
                    v                         v                         v
        +-----------+-----------+ +-----------+-----------+ +-----------+-----------+
        |   Aho-Corasick Trie   | |    Hex BytePattern    | |   Thompson NFA Graph  |
        +-----------+-----------+ +-----------+-----------+ +-----------+-----------+
                    |                         |                         |
                    +-------------------+     |     +-------------------+
                                        |     |     |
                                        v     v     v [Matcher Engines]
                                  +-----------+-----------+
                                  |    Pattern Matches    |
                                  +-----------+-----------+
                                              |
                                              v [Condition VM Evaluator]
                                  +-----------+-----------+
                                  |      Scan Verdict     |
                                  +-----------------------+
```

---

## 🚀 快速开始 (Usage Example)

以下展示了如何加载、编译 YARA 规则，并对输入数据进行匹配扫描：

```mbt check
test {
  // 1. 声明并定义规则
  let rules_text =
    #|rule PHPWebShell {
    #|  meta:
    #|    description = "Detect simple PHP eval webshell"
    #|  strings:
    #|    $eval = "eval"
    #|    $get = "$_GET"
    #|  condition:
    #|    $eval and $get
    #|}
  
  // 2. 编译规则
  let compiled = try! @src.compile_rules(rules_text)
  
  // 3. 扫描恶意载荷 (Payload)
  let payload = b"<?php eval($_GET['cmd']); ?>"
  let matches = @src.scan_bytes(compiled, payload)
  
  // 4. 断言验证匹配结果
  inspect(matches.length(), content="1")
  inspect(matches[0].rule_name, content="\"PHPWebShell\"")
}
```

---

## 🛠️ 本地开发与贡献 (Development)

请遵循 [CONTRIBUTING.md](CONTRIBUTING.md) 的说明：

```bash
# 格式化代码
moon fmt

# 运行类型检查
moon check

# 执行单元与集成测试
moon test

# 使用 JS 目标运行命令行工具
moon run --target js cmd/main -- -r test_rules/webshell.yara -f test_files/webshell.php
```

---

## 🛡️ 开源协议 (License)

本项目遵循 **Apache-2.0** 开源许可证。
