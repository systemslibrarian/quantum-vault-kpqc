# Contributing to Quantum Vault

Thank you for your interest in contributing! This document outlines the process and guidelines.

## Code of Conduct

Be respectful. This is an educational project — questions and constructive feedback are welcome.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc.git
cd crypto-lab-quantum-vault-kpqc

# Build and test Rust
cargo build --workspace
cargo test --workspace

# Build and test web demo
cd web-demo
npm ci
npm run test
npm run build
```

## Development Setup

### Prerequisites

- **Rust**: stable toolchain (1.75+)
- **Node.js**: 20+ with npm
- **Optional**: `cargo-fuzz` for fuzzing, nightly Rust for WASM builds

### Useful Commands

```bash
# Run all Rust tests (including property tests)
cargo test --workspace

# Run clippy lints
cargo clippy --workspace -- -W clippy::all

# Check formatting
cargo fmt --all -- --check

# Run web demo tests
cd web-demo && npm run test

# Run fuzz targets (requires nightly + cargo-fuzz)
cargo +nightly fuzz run fuzz_shamir_roundtrip -- -max_total_time=60
```

## Submitting Changes

### Pull Request Process

1. **Fork** the repository and create a feature branch from `main`
2. **Write tests** for any new functionality
3. **Run the test suite** before submitting: `cargo test --workspace && cd web-demo && npm run test`
4. **Ensure no lint warnings**: `cargo clippy --workspace` and `cargo fmt --all -- --check`
5. **Open a PR** with a clear description of the change

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `chore`: Maintenance (CI, deps, etc.)

**Examples:**
```
feat(shamir): add share validation before reconstruction
fix(container): reject truncated input in from_bytes
test(property): add nonce freshness property test
docs: update README with demo credentials disclaimer
```

## What to Work On

Check the [Issues](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/issues) tab for open tasks. Look for labels:

- `good first issue` — Beginner-friendly tasks
- `help wanted` — Areas where contributions are especially welcome
- `documentation` — Docs improvements

### Areas Needing Help

- **Testing**: Additional edge cases, cross-browser testing
- **Documentation**: Inline comments, API examples, translations
- **Accessibility**: ARIA labels, keyboard navigation
- **Performance**: WASM optimization, bundle size reduction

## Code Style

### Rust

- Follow `rustfmt` defaults (run `cargo fmt`)
- Add `#[must_use]` to functions returning `Result` or important values
- Use `expect("context")` over `unwrap()` where possible
- Add rustdoc comments (`///`) to all public items

### TypeScript

- Use strict mode (already enabled)
- Prefer `const` over `let`
- Add JSDoc comments to exported functions
- Avoid `any` — define proper types

## Testing Guidelines

- **Unit tests**: Test individual functions in isolation
- **Property tests**: Use `proptest` for invariants over random inputs
- **Integration tests**: Test full pipelines (encrypt→decrypt, split→reconstruct)
- **Fuzz tests**: Add fuzz targets for parsing and cryptographic operations

### Running Specific Tests

```bash
# Run only property tests
cargo test --test property_tests

# Run only a specific test
cargo test shamir_roundtrip

# Run web tests in watch mode
cd web-demo && npm run test -- --watch
```

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, email the maintainers directly or use GitHub's private security advisory feature.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
