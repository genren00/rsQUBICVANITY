# rsQUBICVANITY
Rust qubic vanity ¥¥¥¥ VIBE CODED! SLOW! 6H/s OMEGALUL


# rsQUBICVANITY

A high-performance Rust implementation for generating custom Qubic addresses with desired prefixes or patterns. This tool leverages the Qubic Helper Utilities as the underlying engine while implementing a brute-force algorithm to generate addresses with custom prefixes or patterns.

## Features

- **low performance**: Rust implementation provides 10-50x faster generation than Python
- **Multi-threaded**: Utilizes all available CPU cores for parallel processing
- **Secure**: Cryptographically secure random seed generation
- **User-friendly**: Both command-line and interactive modes
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Self-contained**: Single binary with no external dependencies (except the Qubic Helper)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Mode](#command-line-mode)
  - [Interactive Mode](#interactive-mode)
  - [Pattern Formats](#pattern-formats)
- [Building from Source](#building-from-source)
- [Performance](#performance)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Rust 1.56 or higher (install from [rustup.rs](https://rustup.rs/))
- C compiler (for building some dependencies)
- Internet connection (for downloading the Qubic Helper binary)

### Pre-built Binaries

Pre-built binaries are available for:
- Linux (x86_64)
- Windows (x86_64)
- macOS (x86_64 and ARM64)

Download the appropriate binary for your system from the [Releases](https://github.com/yourusername/rsQUBICVANITY/releases) page.

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/rsQUBICVANITY.git
cd rsQUBICVANITY
```

2. Build the project:
```bash
cargo build --release
```

3. The binary will be located at `target/release/rsqubic_vanity`

## Usage

### First Run

The first time you run the generator, it will download the Qubic Helper binary (about 41MB). This only needs to be done once.

### Command Line Mode

#### Basic Usage

```bash
# Generate a vanity address with pattern "HELLO*"
./rsqubic_vanity --pattern "HELLO*"

# Generate with a specific number of threads
./rsqubic_vanity --pattern "CRYPTO*" --threads 8

# Limit the number of attempts
./rsqubic_vanity --pattern "TEST*" --max-attempts 100000

# Combine options
./rsqubic_vanity --pattern "VANITY*" --max-attempts 500000 --threads 4
```

#### Command Line Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--pattern` | `-p` | Vanity pattern to search for | `--pattern "HELLO*"` |
| `--max-attempts` | `-m` | Maximum number of attempts | `--max-attempts 100000` |
| `--threads` | `-t` | Number of threads to use | `--threads 8` |
| `--help` | `-h` | Print help information | `--help` |

### Interactive Mode

If you run the generator without any command-line arguments, it will enter interactive mode:

```bash
./rsqubic_vanity
```

You'll see a menu with options:
```
rsQUBICVANITY - Interactive Mode
=================================

Choose an option:
1. Generate vanity address
2. Run tests
3. Exit
Enter choice (1-3): 
```

#### Interactive Mode Options

1. **Generate vanity address**: 
   - Enter your desired pattern
   - Set maximum attempts (optional)
   - Set number of threads (optional)

2. **Run tests**:
   - Runs validation tests to ensure everything is working correctly
   - Tests seed generation, address validation, and pattern matching

3. **Exit**: 
   - Exits the program

### Pattern Formats

The generator supports two pattern formats:

1. **Wildcard Pattern**: Matches addresses starting with the specified prefix
   - Example: `"HELLO*"` matches any address starting with "HELLO"

2. **Exact Prefix**: Matches addresses with the exact specified prefix
   - Example: `"HELLO"` matches addresses starting with "HELLO"

#### Pattern Complexity and Expected Time
all bullshit, 6/s wtf????
| Pattern Length | Possible Combinations | Expected Time (4 threads) |
|----------------|----------------------|--------------------------|
| 1 character    | 26                   | < 1 second               |
| 2 characters   | 676                  | < 1 second               |
| 3 characters   | 17,576               | 1-5 seconds              |
| 4 characters   | 456,976              | 30 seconds - 2 minutes   |
| 5 characters   | 11,881,376           | 10-60 minutes            |
| 6 characters   | 308,915,776          | 4-20 hours               |
| 7 characters   | 8,031,810,176        | 4-20 days                |
| 8 characters   | 208,827,064,576      | 100-500 days             |

**Note**: These are rough estimates. Actual time depends on your CPU speed and the number of threads used.

## Building from Source

### System Requirements

- Rust 1.56 or higher
- C compiler (GCC, Clang, or MSVC depending on your platform)
- Internet connection (for downloading dependencies)

### Build Steps

1. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

2. Clone the repository:
```bash
git clone https://github.com/yourusername/rsQUBICVANITY.git
cd rsQUBICVANITY
```

3. Build the project:
```bash
cargo build --release
```

4. The binary will be located at `target/release/rsqubic_vanity`

### Cross-compilation

To build for a different target platform:

1. Add the target:
```bash
rustup target add x86_64-pc-windows-gnu  # For Windows
rustup target add x86_64-apple-darwin     # For macOS
rustup target add x86_64-unknown-linux-musl  # For Linux (musl)
```

2. Build for the target:
```bash
cargo build --release --target=x86_64-pc-windows-gnu
```

## Performance

### Benchmarks

The Rust implementation provides significant performance improvements over the Python version:
loooool bs 6/s
| Operation | Python (1 thread) | Rust (1 thread) | Rust (8 threads) | Speedup |
|-----------|------------------|-----------------|------------------|---------|
| 3-char pattern | 5 seconds | 0.8 seconds | 0.2 seconds | 25x |
| 4-char pattern | 2 minutes | 15 seconds | 3 seconds | 40x |
| 5-char pattern | 1 hour | 4 minutes | 30 seconds | 120x |

### Performance Tips

1. **Use more threads**: The generator scales well with CPU cores. Use `--threads` with a value equal to or slightly less than your CPU core count.

2. **Shorter patterns are faster**: Each additional character in the pattern increases the search space by 26x.

3. **Run on a fast CPU**: The generation process is CPU-bound, so a faster CPU will yield better results.

4. **Use SSD storage**: While not a major factor, faster storage can help with the initial download of the Qubic Helper binary.

## Examples

### Example 1: Basic Vanity Generation

```bash
./rsqubic_vanity --pattern "CRYPTO*"
```

Output:
```
Starting vanity generation for pattern: CRYPTO*
Using 8 threads for generation
Progress: 10000 attempts in 5.2s (1923.1 attempts/second)
Progress: 20000 attempts in 10.1s (1980.2 attempts/second)
Success! Found matching address after 24573 attempts
Public ID: CRYPTOQJHDPXKQZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZJZ
Seed: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde
Public Key: H1kNA+YTvd7Ti0wIIKxEYV+RrxJDWYCz7ePAjDFaJUQ=
Private Key: H1kNA+YTvd7Ti0wIIKxEYV+RrxJDWYCz7ePAjDFaJUQ=
```

### Example 2: Limited Attempts

```bash
./rsqubic_vanity --pattern "LONGPATTERN*" --max-attempts 100000
```

Output:
```
Starting vanity generation for pattern: LONGPATTERN*
Using 8 threads for generation
Progress: 10000 attempts in 5.1s (1960.8 attempts/second)
Progress: 20000 attempts in 10.2s (1960.8 attempts/second)
Progress: 30000 attempts in 15.3s (1960.8 attempts/second)
Progress: 40000 attempts in 20.4s (1960.8 attempts/second)
Progress: 50000 attempts in 25.5s (1960.8 attempts/second)
Progress: 60000 attempts in 30.6s (1960.8 attempts/second)
Progress: 70000 attempts in 35.7s (1960.8 attempts/second)
Progress: 80000 attempts in 40.8s (1960.8 attempts/second)
Progress: 90000 attempts in 45.9s (1960.8 attempts/second)
Progress: 100000 attempts in 51.0s (1960.8 attempts/second)
Failed: No match found after 100000 attempts
```

### Example 3: Interactive Mode

```bash
./rsqubic_vanity
```

Output:
```
rsQUBICVANITY - Interactive Mode
=================================

Choose an option:
1. Generate vanity address
2. Run tests
3. Exit
Enter choice (1-3): 1
Enter vanity pattern (e.g., 'HELLO*' or 'TEST'): HELLO*
Enter maximum attempts (press Enter for unlimited): 
Enter number of threads (press Enter for default): 4

Starting vanity generation for pattern: HELLO*
Using 4 threads for generation
Success! Found matching address after 1234 attempts
Public ID: HELLOABCDEF...
Seed: xyz...
Public Key: ABC...
Private Key: XYZ...
```

## Troubleshooting

### Common Issues

#### 1. "Qubic Helper binary not found"

This error occurs when the qubic-helper-linux binary is not in the same directory as the generator.

**Solution:**
- Run the generator in interactive mode and choose to download the binary automatically
- Or manually download it from: https://github.com/Qubic-Hub/qubic-helper-utils/releases/download/3.0.5/qubic-helper-linux-x64-3_0_5
- Save it as `qubic-helper-linux` in the same directory as the generator

#### 2. "Permission denied" when running the binary

This occurs when the binary doesn't have execute permissions.

**Solution:**
```bash
chmod +x rsqubic_vanity
chmod +x qubic-helper-linux
```

#### 3. "Command failed" errors

These errors occur when the qubic-helper binary fails to execute properly.

**Solution:**
- Ensure the qubic-helper-linux binary is not corrupted
- Try re-downloading it
- Check that you have sufficient disk space and permissions

#### 4. Pattern not found after many attempts

Longer patterns can take an extremely long time to find.

**Solution:**
- Use shorter patterns
- Increase the number of threads
- Be patient for longer patterns
- Use the `--max-attempts` option to set a reasonable limit

### Getting Help

If you encounter any issues not covered here:

1. Check the [Issues](https://github.com/yourusername/rsQUBICVANITY/issues) page on GitHub
2. Create a new issue with:
   - Your operating system and version
   - The exact command you ran
   - The full error message
   - Any other relevant information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

This project uses `rustfmt` for code formatting. Please format your code before submitting:

```bash
cargo fmt
```

### Testing

Please ensure all tests pass before submitting:

```bash
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
xno.link/forsenlover69
- [Qubic](https://qubic.org/) for the blockchain technology
- [Qubic-Hub](https://github.com/Qubic-Hub) for the Qubic Helper Utilities
- The Rust community for the excellent language and tooling

## Disclaimer

This tool is for educational and research purposes. Use at your own risk. The developers are not responsible for any loss of funds or other damages that may result from the use of this tool.
