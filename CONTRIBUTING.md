# Contributing to MoonYara

Thank you for your interest in contributing to **MoonYara**! We welcome all contributions, from bug reports to new features, optimizations, and documentation improvements.

## Development Workflow

1. Fork the repository on GitLink or GitHub.
2. Install the [MoonBit toolchain](https://moonbitlang.com).
3. Write your code and add corresponding tests in `*_test.mbt`.
4. Run formatting, type checking, and tests:
   ```bash
   moon fmt
   moon check
   moon test
   ```
5. Submit a Pull Request.

## Code Style
Please adhere to standard MoonBit style. We encourage the use of `moon fmt` to automatically format all files before committing.

## Submitting a PR
When submitting a PR, make sure your PR title follows the conventional commits format, e.g.:
- `feat(regex): implement Thompson NFA engine`
- `fix(hex): resolve off-by-one wildcard alignment`
- `docs: update performance benchmarks`
