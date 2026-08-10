# BinScope

**BinScope** is a static binary analysis tool written in Rust.

The goal of the project is to inspect executable files and provide useful information for reverse engineering, malware analysis, and security research.

The project is being developed from scratch as a learning project focused on **Rust, binary formats, systems programming, reverse engineering, and cybersecurity**.

> **Status:** Early development

## Goals

BinScope aims to progressively support static analysis of common executable formats through a modular analysis engine.

Planned capabilities include:

* PE analysis
* ELF analysis
* File type and architecture detection
* Section analysis
* Import and export inspection
* String extraction
* File hashing
* Entropy analysis
* Security mitigation detection
* Basic disassembly
* Suspicious API detection
* JSON report generation

The project will initially focus on a **command-line interface (CLI)**. A graphical interface may be considered once the analysis engine is mature.

## Why BinScope?

Understanding how executable files are structured is fundamental to reverse engineering and malware analysis.

Rather than relying entirely on existing analysis libraries, BinScope is being developed from the ground up to understand and implement the underlying concepts:

* Binary file formats
* Binary parsing
* Executable loading
* PE and ELF structures
* Sections and segments
* Symbols
* Imports and exports
* Dynamic linking
* Memory layout
* Security mitigations
* x86/x86-64 instructions

External libraries will be introduced selectively when they provide functionality outside the primary learning objectives of the project.

## Technology

* **Rust**
* Cargo
* Git / GitHub
* GitHub Actions

The project currently uses Rust's standard library for binary reading and format detection. External dependencies will be added deliberately as the project grows.

## Project Status

BinScope is currently in the **foundation and binary detection phase**.

Current progress:

* [x] Rust project created
* [x] Git repository initialized
* [x] Initial project commit
* [x] GitHub repository
* [x] Continuous Integration
* [x] Initial project architecture
* [x] Binary format abstraction
* [x] Initial PE signature detection
* [x] Initial ELF signature detection
* [x] Unit tests
* [ ] CLI foundation
* [ ] Robust file type detection
* [ ] Architecture detection
* [ ] PE parser
* [ ] ELF parser
* [ ] Static analysis modules
* [ ] Reporting system

## Roadmap

### Phase 1 — Foundation

* [x] Project architecture
* [x] Initial error-free build
* [x] Testing infrastructure
* [x] Continuous Integration
* [ ] CLI foundation
* [ ] Error handling
* [ ] Logging

### Phase 2 — Binary Detection

* [x] Initial binary signature detection
* [ ] Read binary files from CLI
* [ ] Robust file format detection
* [ ] Detect architecture
* [ ] Detect endianness
* [ ] Basic file metadata

### Phase 3 — PE Analysis

* [ ] DOS Header
* [ ] PE Signature
* [ ] COFF Header
* [ ] Optional Header
* [ ] Section Table
* [ ] Imports
* [ ] Exports

### Phase 4 — ELF Analysis

* [ ] ELF Header
* [ ] Program Headers
* [ ] Section Headers
* [ ] Symbols
* [ ] Dynamic Linking
* [ ] Relocations

### Phase 5 — Static Analysis

* [ ] Strings
* [ ] Cryptographic hashes
* [ ] Entropy
* [ ] Security mitigations
* [ ] Suspicious imports
* [ ] Basic disassembly

### Phase 6 — Reporting

* [ ] Human-readable CLI output
* [ ] JSON output
* [ ] Analysis reports

### Future

* [ ] YARA integration
* [ ] Function analysis
* [ ] Control-flow graphs
* [ ] Plugin architecture
* [ ] Mach-O support
* [ ] Graphical interface

## Development

Build the project:

```bash
cargo build
```

Run BinScope:

```bash
cargo run -- <file>
```

Run tests:

```bash
cargo test
```

Check formatting:

```bash
cargo fmt --all -- --check
```

Run Clippy:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Continuous Integration

Every push to `main` and every pull request targeting `main` is checked automatically using GitHub Actions.

The CI pipeline currently verifies:

* Rust formatting with `rustfmt`
* Compilation with `cargo check`
* Unit tests with `cargo test`
* Code quality with Clippy

Warnings are treated as errors during Clippy checks to maintain a clean codebase.

## Learning Objectives

BinScope is also a practical exploration of:

* Rust ownership and borrowing
* Error handling with `Result` and `Option`
* Traits and generics
* Modules and crate architecture
* Binary parsing
* Systems programming
* Reverse engineering fundamentals
* Static malware analysis
* Software testing
* CI/CD
* Git and GitHub workflows
* Open-source development

## Security Scope

BinScope is intended for **defensive security research, reverse engineering, malware analysis, and educational purposes**.

The project focuses on understanding executable formats and extracting information from binaries without executing them.

## License

This project is licensed under the MIT License.
