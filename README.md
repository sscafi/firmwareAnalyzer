# Enhanced Firmware Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Python-based tool for analyzing firmware images, performing static security analysis, and generating detailed reports. This enhanced version provides improved performance, better error handling, and extensive vulnerability scanning capabilities.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Analysis Methods](#analysis-methods)
- [Output Formats](#output-formats)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Analysis Capabilities
- **Intelligent Firmware Extraction**: Supports SquashFS, JFFS2, UBI, ZIP, 7-zip with automatic format detection
- **Advanced String Analysis**: Categorized pattern matching for credentials, network artifacts, cryptographic materials, and commands
- **ELF Security Analysis**: Comprehensive binary analysis including security feature detection (NX bit, stack canaries, PIE, RELRO)
- **Multi-Source Vulnerability Scanning**: Integration with NVD, OSV, and CVE databases
- **File Type Classification**: Automated file type detection and categorization
- **Cryptographic Material Detection**: Certificate analysis and key extraction
- **Configuration Security Review**: Analysis of config files for security misconfigurations
- **Hash-based Integrity Verification**: MD5, SHA256 checksums for all files

### Performance & Reliability
- **Parallel Processing**: Multi-threaded analysis for improved performance
- **Timeout Protection**: Configurable timeouts to prevent hanging operations
- **Memory Efficient**: Optimized for large firmware images
- **Comprehensive Logging**: Detailed logging with configurable levels
- **Error Recovery**: Graceful handling of corrupted or malformed files

### Reporting & Output
- **Dual Format Reports**: JSON and PDF report generation
- **Structured Results**: Organized, searchable analysis results
- **Progress Tracking**: Real-time analysis progress indication
- **Metadata Tracking**: Version control and analysis timestamps

## Installation

### Prerequisites
- Python 3.8 or higher
- Linux-based system (recommended for best tool compatibility)

### Clone Repository
```bash
git clone https://github.com/your-username/firmware-analyzer.git
cd firmware-analyzer
```

### Install Dependencies

#### Core Dependencies
```bash
pip install -r requirements.txt
```

#### System Dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
    binwalk \
    squashfs-tools \
    python3-magic \
    yara \
    qemu-system-arm
```

#### Optional Tools
```bash
# For advanced extraction
sudo apt-get install -y \
    jefferson \
    ubi-reader \
    p7zip-full

# For enhanced analysis
pip install \
    angr \
    capstone \
    scapy \
    scikit-learn
```

### Requirements.txt
```
python-magic>=0.4.24
yara-python>=4.2.0
requests>=2.28.0
pyelftools>=0.29
reportlab>=3.6.0
pathlib>=1.0.1
```

## Quick Start

### Command Line Usage
```bash
# Basic analysis
python firmware_analyzer.py firmware.bin

# Advanced analysis with custom settings
python firmware_analyzer.py firmware.bin \
    --workers 8 \
    --timeout 600 \
    --format both

# Help
python firmware_analyzer.py --help
```

### Python API Usage
```python
from firmware_analyzer import FirmwareAnalyzer, AnalysisConfig

# Basic usage
analyzer = FirmwareAnalyzer('firmware.bin')
success = analyzer.run_analysis()

# Advanced configuration
config = AnalysisConfig(
    max_workers=8,
    timeout=600,
    output_format='both',
    enable_emulation=True
)

analyzer = FirmwareAnalyzer('firmware.bin', config)
results = analyzer.run_analysis()

# Access results
print(f"Found {len(analyzer.results['elf_analysis'])} ELF files")
print(f"Identified {len(analyzer.results['vulnerabilities']['nvd'])} potential vulnerabilities")
```

## Usage

### Command Line Options

```bash
python firmware_analyzer.py [OPTIONS] FIRMWARE_PATH

Arguments:
  FIRMWARE_PATH    Path to the firmware file to analyze

Options:
  --workers INTEGER     Number of worker threads (default: 4)
  --timeout INTEGER     Timeout in seconds for operations (default: 300)
  --format [json|pdf|both]  Output format (default: json)
  --help               Show this message and exit
```

### Python Module Usage

```python
from firmware_analyzer import FirmwareAnalyzer, AnalysisConfig, VulnerabilityInfo

# Create configuration
config = AnalysisConfig(
    max_workers=4,
    timeout=300,
    enable_emulation=False,
    enable_network_analysis=False,
    enable_yara_scan=True,
    yara_rules_path="rules.yar",
    output_format="json"
)

# Initialize analyzer
analyzer = FirmwareAnalyzer("/path/to/firmware.bin", config)

# Run analysis
if analyzer.run_analysis():
    print("Analysis completed successfully")
    
    # Access specific results
    vulnerabilities = analyzer.results.get('vulnerabilities', {})
    elf_files = analyzer.results.get('elf_analysis', [])
    strings = analyzer.results.get('interesting_strings', {})
else:
    print("Analysis failed")
```

## Configuration

### AnalysisConfig Class

```python
@dataclass
class AnalysisConfig:
    max_workers: int = 4                    # Number of parallel workers
    timeout: int = 300                      # Operation timeout (seconds)
    enable_emulation: bool = False          # Enable firmware emulation
    enable_network_analysis: bool = False   # Enable network traffic analysis
    enable_yara_scan: bool = True          # Enable YARA scanning
    yara_rules_path: str = "rules.yar"     # Path to YARA rules file
    output_format: str = "json"            # Output format: json, pdf, both
```

### Environment Variables

```bash
# Optional: Set custom paths
export YARA_RULES_PATH="/path/to/custom/rules.yar"
export FIRMWARE_TEMP_DIR="/tmp/firmware_analysis"
export LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
```

## Analysis Methods

### Core Analysis Pipeline

1. **`extract_firmware()`**
   - Automatic format detection (SquashFS, JFFS2, UBI, ZIP, 7-zip)
   - Fallback to binwalk for unknown formats
   - Timeout protection and error handling

2. **`analyze_strings()`**
   - Categorized pattern matching:
     - **Credentials**: passwords, keys, tokens, secrets
     - **Network**: IPs, URLs, emails, ports
     - **Crypto**: certificates, SSH keys, hex strings
     - **Commands**: system binaries and scripts
   - Parallel processing with configurable workers
   - Memory-efficient processing for large files

3. **`analyze_elf_files()`**
   - Architecture detection and entry point analysis
   - Security feature assessment:
     - NX bit (No-eXecute) protection
     - Stack canaries
     - Position Independent Executable (PIE)
     - RELRO (Relocation Read-Only)
     - FORTIFY_SOURCE
   - Import/export function analysis
   - Symbol table extraction

4. **`scan_for_vulnerabilities()`**
   - **NVD Integration**: National Vulnerability Database scanning
   - **OSV Database**: Open Source Vulnerabilities
   - **CVE CIRCL**: CVE database integration
   - Software component identification
   - Version detection and matching
   - Severity scoring and classification

5. **`calculate_hashes()`**
   - MD5 and SHA256 hash calculation
   - File size tracking
   - Progress reporting for large datasets
   - Integrity verification support

### Security-Focused Methods

6. **`_analyze_single_elf()`**
   - Deep ELF binary analysis
   - Security mitigation detection
   - Function import/export mapping
   - Potential vulnerability identification

7. **`_identify_software_components()`**
   - Version string extraction
   - Component identification using regex patterns
   - Software inventory generation

### Utility Methods

8. **`_safe_decode()`**
   - Multi-encoding text decoding
   - Graceful handling of binary data
   - Error-resistant string processing

9. **`_get_text_files()`**
   - Intelligent text file identification
   - MIME type detection
   - Size-based filtering for performance

## Output Formats

### JSON Report Structure

```json
{
  "metadata": {
    "firmware_path": "/path/to/firmware.bin",
    "analysis_date": "2024-01-15 10:30:45",
    "analyzer_version": "2.0"
  },
  "extraction": {
    "success": true,
    "method": "unsquashfs -d /path/extracted /path/firmware.bin",
    "file_type": "Squashfs filesystem"
  },
  "interesting_strings": {
    "/path/to/file": {
      "credentials": ["admin:password"],
      "network": ["192.168.1.1", "http://example.com"],
      "crypto": ["-----BEGIN RSA PRIVATE KEY-----"]
    }
  },
  "elf_analysis": [
    {
      "file": "/path/to/binary",
      "architecture": "ARM",
      "entry_point": "0x8000",
      "security_features": {
        "nx_bit": true,
        "stack_canary": false,
        "pie": true
      }
    }
  ],
  "vulnerabilities": {
    "nvd": [
      {
        "id": "CVE-2024-1234",
        "description": "Buffer overflow in component X",
        "severity": "high",
        "cvss_score": 8.5,
        "affected_files": ["/path/to/vulnerable/file"]
      }
    ],
    "summary": {
      "total": 15,
      "high": 3,
      "medium": 7,
      "low": 5
    }
  },
  "file_hashes": {
    "/path/to/file": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
      "size": 1024
    }
  }
}
```

### PDF Report Features

- Executive summary with key findings
- Vulnerability assessment with severity ratings
- File inventory with security classifications
- Hash verification tables
- Detailed technical appendix

## Dependencies

### Required Python Packages

| Package | Version | Purpose |
|---------|---------|---------|
| python-magic | >=0.4.24 | File type detection |
| yara-python | >=4.2.0 | Pattern matching and malware detection |
| requests | >=2.28.0 | HTTP requests for vulnerability databases |
| pyelftools | >=0.29 | ELF file analysis |
| reportlab | >=3.6.0 | PDF report generation |

### Optional Packages

| Package | Purpose | Installation |
|---------|---------|--------------|
| angr | Binary analysis and symbolic execution | `pip install angr` |
| capstone | Disassembly engine | `pip install capstone` |
| scapy | Network packet analysis | `pip install scapy` |
| scikit-learn | Machine learning for anomaly detection | `pip install scikit-learn` |

### System Tools

| Tool | Purpose | Installation (Ubuntu/Debian) |
|------|---------|------------------------------|
| binwalk | Firmware extraction | `apt install binwalk` |
| unsquashfs | SquashFS extraction | `apt install squashfs-tools` |
| jefferson | JFFS2 extraction | `pip install jefferson` |
| ubireader | UBI extraction | `pip install ubi-reader` |

## Performance Considerations

### Optimization Tips

1. **Adjust Worker Threads**: Use `--workers` to match your CPU cores
2. **Set Appropriate Timeouts**: Large firmware may need `--timeout 1200`
3. **Memory Usage**: Analysis of large firmware (>100MB) may require 4GB+ RAM
4. **Storage**: Extracted firmware can be 2-10x the original size

### Benchmarks

| Firmware Size | Extraction Time | Analysis Time | Memory Usage |
|---------------|----------------|---------------|--------------|
| 8MB | 5s | 30s | 256MB |
| 32MB | 15s | 120s | 512MB |
| 128MB | 60s | 480s | 2GB |

## Troubleshooting

### Common Issues

1. **Extraction Fails**
   - Ensure system tools are installed
   - Check file permissions
   - Verify firmware format is supported

2. **Memory Errors**
   - Reduce worker count with `--workers 2`
   - Increase system swap space
   - Process smaller firmware chunks

3. **Timeout Errors**
   - Increase timeout with `--timeout 600`
   - Check for corrupted firmware
   - Monitor system resources

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python firmware_analyzer.py firmware.bin

# Check log files
tail -f firmware_analysis.log
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/your-username/firmware-analyzer.git
cd firmware-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 firmware_analyzer.py
black firmware_analyzer.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

This tool is designed for legitimate security research and should only be used on firmware that you own or have explicit permission to analyze. Users are responsible for complying with applicable laws and regulations.

## Changelog

### Version 2.0
- Complete rewrite with enhanced architecture
- Parallel processing support
- Improved vulnerability scanning
- Better error handling and logging
- Dual-format reporting (JSON/PDF)
- Configuration management system
- Performance optimizations

### Version 1.0
- Initial release
- Basic firmware extraction and analysis
- Simple reporting capabilities

---

**Disclaimer**: This tool is provided for educational and research purposes. Always ensure you have proper authorization before analyzing firmware.
