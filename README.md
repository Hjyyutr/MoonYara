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

## 🛠️ 安装与准备 (Installation & Setup)

### 1. 安装 MoonBit 工具链
要构建和开发 MoonYara，请首先安装最新版本的 MoonBit 编译器工具链：
- **Linux / macOS**:
  ```bash
  curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
  # 并根据终端提示将 ~/.moon/bin 添加至环境变量 PATH 中
  ```
- **Windows (PowerShell)**:
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
  irm https://cli.moonbitlang.com/install/powershell.ps1 | iex
  ```

### 2. 依赖索引准备
本项目依赖官方通用扩展库 `moonbitlang/x`。首次克隆仓库或更新工具链后，请在项目根目录运行以下命令更新包管理器索引并拉取依赖：
```bash
moon update
```

---

## 🌐 浏览器与 WebAssembly 复现步骤 (Wasm & Browser Guide)

MoonYara 的核心匹配引擎 `src` 是 **100% 纯 MoonBit 实现，无任何系统 FFI/IO 依赖 (Zero-FFI)**，可直接编译为 WebAssembly 字节码并在现代浏览器前端直接对用户上传的文件进行高速离线扫描，防止恶意木马和 Webshell 被上传至后端服务器。

### 复现步骤：

1. **编译为 JavaScript / WebAssembly 目标**
   在项目根目录下，使用 `moon` 编译器将引擎打包编译为相应的目标字节码或脚本：
   - 编译为 JavaScript 目标代码：
     ```bash
     moon build --target js
     ```
   - 编译为标准的 WebAssembly (wasm-gc) 目标字节码：
     ```bash
     moon build --target wasm-gc
     ```

2. **在浏览器或 Node.js 环境中引入**
   编译完成后，核心匹配逻辑会被生成在 `_build` 目录中。您可以在前端网页中直接加载该 Wasm 模块，编写简单的 JavaScript 接口调用引擎。例如在 JS/TS 中：
   ```javascript
   import { compile_rules, scan_bytes } from './path/to/generated/moonyara.js';

   // 编译 YARA 规则
   const ruleText = `
     rule MaliciousEval {
       strings:
         $eval = "eval("
       condition:
         $eval
     }
   `;
   const compiledRules = compile_rules(ruleText);

   // 用户在 input 文件上传框中选择的文件转换为 Uint8Array
   const fileData = new Uint8Array([0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, 0x65, 0x76, 0x61, 0x6c, 0x28, 0x24, 0x5f, 0x47, 0x45, 0x54, 0x2e]);
   
   // 触发离线扫描
   const matches = scan_bytes(compiledRules, fileData);

   if (matches.length > 0) {
     console.warn(`[ALERT] 检测到恶意特征匹配：\${matches[0].rule_name}`);
     // 阻止文件向后端服务器上传
   } else {
     console.log("[CLEAN] 文件安全，允许上传。");
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
