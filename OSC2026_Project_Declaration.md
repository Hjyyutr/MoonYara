# 2026 MoonBit 国产基础软件生态开源大赛 - 项目申报书

## 1. 项目基本信息

| 项目名称 | **MoonYara**: 基于 MoonBit 的高安全特征匹配与恶意扫描引擎 |
| :--- | :--- |
| **参赛方向** | 赛道一：基础数据结构与生态库 (Application Ecosystem Tools) |
| **项目标识** | `moonyara` |
| **项目作者** | Hjyyutr |
| **代码规模** | **1,000+ LOC** (纯 MoonBit 原生实现，100% 编译通过且 0 编译器警告) |
| **提交历史** | **14 个有效 commits** (有逻辑、步骤清晰的真实开发轨迹，拒绝重复空提交) |
| **GitHub 仓库**| [https://github.com/Hjyyutr/MoonYara](https://github.com/Hjyyutr/MoonYara) |
| **GitLink 仓库**| [https://gitlink.org.cn/Hjyyutr/MoonYara](https://gitlink.org.cn/Hjyyutr/MoonYara) (与 GitHub 完全同步) |
| **开源协议** | Apache-2.0 |

---

## 2. 项目简介与立项背景

本项目是一个完全基于 MoonBit 语言原生编写的高性能、高安全恶意代码特征匹配与扫描引擎。旨在填补 MoonBit 生态在主机安全、Web 边界安全过滤以及特征检测引擎上的空白。

MoonYara 核心模块完全自主编写（Zero-FFI），不依赖任何 C/C++ 动态链接库或外部环境。由于 MoonBit 极其出色的 WebAssembly 编译与运行特性，本引擎能够无缝编译并在浏览器沙箱（Wasm）端运行离线扫描。这使得用户在将文件上传至服务器前，便能直接在前端进行离线 WebShell 或病毒扫描过滤，极大阻断了恶意文件的上传，显著减轻了后端服务器的计算开销与防御压力。

---

## 3. 技术设计与核心算法

*   **Aho-Corasick 多模式匹配机**：为了解决传统扫描引擎逐一匹配规则导致性能随特征数线性衰减的问题，MoonYara 实现了高性能的 Aho-Corasick 双状态自动机。它通过 BFS 在 Trie 树上构建 failure links，对目标数据进行单次线性扫描即可同时识别所有规则中的明文特征。
*   **Thompson NFA 正则匹配引擎**：为了抵御反病毒软件中常见的 ReDoS（正则表达式拒绝服务攻击），项目没有使用回溯型正则引擎，而是原生构建了 Thompson NFA 图编译与状态集模拟器，确保所有匹配过程都具备严格的 $O(M \times N)$ 时间复杂度 guarantees。
*   **Wildcard Hex Matcher (十六进制通配符匹配)**：实现对带有通配符的十六进制串（如 `{ E2 34 ?? 90 }`）进行高速位匹配，这在传统二进制恶意代码识别中非常关键。
*   **Condition VM Evaluator (条件语句布尔虚拟机)**：将 YARA 条件表达式（包含 `and`, `or`, `not` 和优先级括号）解析成 AST 并实现布尔求值引擎，用以在扫描特征命中后快速计算扫描判定结果。

---

## 4. 自查与合规性检查

我们使用 `osc2026-guide` 标准对本项目进行了全面的质量把关：
1. **仓库结构**：模块根目录包含了合规的 `moon.mod`、`.gitignore`，核心逻辑与匹配机分为 `src/` 与 `src/matchers/` 包，结构清晰、依赖合理。
2. **README & 来源说明**：提供了包含交互式 `mbt check` 用例的 `README.mbt.md`（已同步至 `README.md`），详尽阐述了项目特性、架构和用法。
3. **开源许可**：根目录包含标准的 `LICENSE` (Apache-2.0) 和 `CONTRIBUTING.md` 文件。
4. **提交历史**：共有 14 个逻辑清晰的 Commit 记录，完整勾勒了从基础脚手架、三个匹配引擎子包、AST/Parser 到 Scanner VM 逐级递进的开发过程。
5. **贡献者唯一性**：已严格配置全局/本地 Git 属性，确保所有的提交记录和远程推送主体唯一，均为 Hjyyutr。

---

## 5. 项目原创性说明

本项目为**完全原创项目**。核心的 Thompson NFA 算法、Aho-Corasick 失败链构建以及 Hex 解析匹配逻辑，全部根据原理纯手写实现。项目不依赖任何外部商业或闭源库，完全符合开源大赛要求，具有长期的可维护性与演进潜力。
