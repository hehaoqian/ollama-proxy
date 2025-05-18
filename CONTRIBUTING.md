# Contributing to Ollama API Proxy Server

Thank you for considering contributing to Ollama API Proxy Server! Here are some guidelines to help you get started.

## Development Environment Setup

1. Install the Rust toolchain using [rustup](https://rustup.rs/)
2. Clone the repository
3. Build the project with `cargo build`
4. Run tests with `cargo test`

## Code Style

We use the standard Rust formatting style. Before submitting a pull request, please run:

```bash
cargo fmt
cargo clippy
```

Our CI pipeline will verify that your code follows these guidelines.

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification for commit messages. Please read our [CONVENTIONAL_COMMITS.md](CONVENTIONAL_COMMITS.md) guide for details.

This helps keep the commit history clean and generate accurate changelogs.

## Testing

Please add tests for any new features or bug fixes. Run the test suite with:

```bash
cargo test
```

To run all tests, including those that are ignored by default:

```bash
cargo test -- --ignored
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes using conventional commits format
4. Run the local CI script to verify your changes (`./run-ci.sh`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request using the provided PR template

## Continuous Integration

All pull requests are automatically tested via GitHub Actions. The CI pipeline runs:

- `cargo fmt` to check code formatting
- `cargo clippy` with warnings treated as errors
- `cargo doc` to ensure documentation builds correctly
- `cargo test` to run the test suite

Please make sure these checks pass locally before submitting your PR.

## Feature Flags

The project uses Cargo feature flags to enable optional functionality:

- `database-logging`: Enables logging requests and responses to a SQLite database (enabled by default)

When adding new optional features, please use appropriate feature flags.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License.
