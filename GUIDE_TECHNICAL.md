# Firmware Analyzer: Technical Documentation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FIRMWARE ANALYZER                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  INPUT: firmware.bin (Device OS image)                  │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  1. EXTRACTION PIPELINE                                │  │
│  │     - File type detection (magic bytes)                │  │
│  │     - Format-specific extraction                       │  │
│  │     - Error recovery & fallback mechanisms            │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  2. PARALLEL ANALYSIS WORKERS                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │  │
│  │  │ String   │  │ ELF      │  │ Vulnerability Scan  │ │  │
│  │  │ Analysis │  │ Analysis │  │ (NVD/OSV/CVE)      │ │  │
│  │  └──────────┘  └──────────┘  └──────────────────────┘ │  │
│  │  ┌──────────┐  ┌──────────┐                           │  │
│  │  │ Hash     │  │ YARA     │                           │  │
│  │  │ Calc.    │  │ Rules    │                           │  │
│  │  └──────────┘  └──────────┘                           │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  3. RESULTS AGGREGATION                               │  │
│  │     - Deduplicate findings                            │  │
│  │     - Score severity                                 │  │
│  │     - Generate metadata                              │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  4. REPORT GENERATION                                 │  │
│  │     - JSON structured output                         │  │
│  │     - PDF human-readable report                      │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  OUTPUT: reports/analysis_report_[timestamp].{json|pdf}│  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. Extraction Module (`extract_firmware()`)

**Purpose:** Unpack firmware containers into accessible file systems.

**Implementation:**
```python
def extract_firmware(self) -> bool:
    """
    Detection flow:
    1. Use libmagic (python-magic) to identify file type from magic bytes
    2. Route to appropriate extraction tool:
       - SquashFS → unsquashfs (read-only filesystem, common in embedded)
       - JFFS2 → jefferson (Journaling Flash File System)
       - UBI → ubireader (Unsorted Block Images, NAND flash)
       - ZIP/7z → unzip / 7z (generic archives)
    3. Fallback to binwalk -e (generic binary scanner)
    4. Timeout protection: subprocess.run(..., timeout=config.timeout)
    """
```

**Key Features:**
- **Timeout handling:** Cross-platform (subprocess.TimeoutExpired catches Unix and Windows)
- **Error recovery:** Logs stderr, continues if partial extraction succeeds
- **File type detection:** Examines first ~4KB for magic bytes (0x7f 0x45 0x4c 0x46 for ELF, etc.)

**Extracted Output Structure:**
```
firmware.bin.extracted/
├── bin/
│   ├── httpd (ELF binary)
│   ├── telnetd
│   └── ...
├── etc/
│   ├── config.txt
│   ├── password (hardcoded credentials potentially here)
│   └── ...
├── lib/
│   ├── libc.so.0
│   └── ...
└── [filesystem structure varies by source]
```

---

### 2. String Analysis Module (`analyze_strings()`)

**Purpose:** Extract meaningful patterns from binary and text files.

**Regex Categories:**

#### **Credentials**
```regex
password\s*[:=]\s*[^\s\n]+
admin\s*[:=]\s*[^\s\n]+
root\s*[:=]\s*[^\s\n]+
token\s*[:=]\s*[^\s\n]+
secret\s*[:=]\s*[^\s\n]+
key\s*[:=]\s*[^\s\n]+
```

Examples found:
- `password=admin123` ❌
- `root:toor` ❌
- `API_TOKEN=eyJhbGc...` ⚠️

#### **Network Artifacts**
```regex
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b    # IPv4 addresses
https?://[^\s\n]+                     # URLs/HTTP(S)
ftp://[^\s\n]+                        # FTP URLs
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}  # Emails
:[0-9]{1,5}\b                        # Ports
```

Examples: `192.168.1.1`, `http://malicious-server.com:8080`, etc.

#### **Cryptographic Material**
```regex
-----BEGIN [A-Z ]+-----              # PEM headers (RSA/DSA keys)
-----END [A-Z ]+-----                # PEM footers
[A-Fa-f0-9]{32,}                     # Hex strings (potential keys)
ssh-rsa [A-Za-z0-9+/=]+             # SSH keys
```

#### **System Commands**
```regex
/bin/[a-zA-Z0-9_-]+
/usr/bin/[a-zA-Z0-9_-]+
/sbin/[a-zA-Z0-9_-]+
sudo [a-zA-Z0-9_-]+
chmod 777                            # Dangerous permissions
```

**Implementation Details:**
- **Multithreading:** `concurrent.futures.ThreadPoolExecutor(max_workers=config.max_workers)`
- **File filtering:** Only analyzes text files (`.txt`, `.conf`, `.sh`, etc.) or files with MIME type `text/*`
- **Encoding handling:** Tries UTF-8 → Latin-1 → ASCII → CP1252 (with fallback to `decode(errors='ignore')`)
- **Memory efficiency:** Limits file reads to 1 MB per file
- **Deduplication:** `list(set(matches))` removes duplicate findings

---

### 3. ELF Analysis Module (`analyze_elf_files()`)

**Purpose:** Examine compiled binaries for security features and metadata.

**ELF Structure Review:**
```
[ELF Header]           → Magic bytes (0x7f 0x45 0x4c 0x46)
├── e_machine          → Architecture (ARM, x86, MIPS, etc.)
├── e_type             → File type (executable, shared library, relocatable)
├── e_entry            → Entry point address
│
[Program Headers]      → Runtime memory layout
│
[Section Headers]      → Compiler/linker metadata
├── .text              → Executable code
├── .data              → Initialized data
├── .bss               → Uninitialized data
├── .symtab            → Symbol table (debug info)
├── .dynsym            → Dynamic symbol table
├── .note.GNU-stack    → Stack executable flag
│
[Symbol Table]
├── Imports (.dynsym)  → External functions referenced
└── Exports            → Functions this binary provides
```

**Security Features Detection:**

```python
def _analyze_single_elf(self, file_path):
    """
    1. NX Bit (No-eXecute):
       - Check .note.GNU-stack section
       - sh_flags & 0x1 == 0 → NX enabled (stack not executable)
       - Prevents ROP/stack overflow code execution
    
    2. Stack Canaries:
       - Look for __stack_chk_fail symbol
       - Indicates -fstack-protector compiler flag
       - Catches stack overflow attempts at runtime
    
    3. PIE (Position Independent Executable):
       - e_type == ET_DYN (3)
       - Binary can be loaded at any address
       - Defeats ret2libc attacks (ASLR requirement)
    
    4. RELRO (Relocation Read-Only):
       - Check for .gnu.relro section
       - Makes GOT (Global Offset Table) read-only after startup
       - Prevents GOT overwrite attacks
    
    5. FORTIFY_SOURCE:
       - Look for _FORTIFY_SOURCE symbol
       - Compiler flag that adds buffer overflow checks
    """
```

**Binary Metadata Extracted:**
```json
{
  "file": "/path/to/binary",
  "architecture": "ARM",
  "entry_point": "0x8000",
  "file_type": "Executable",
  "sections": [".text", ".data", ".bss", ".symtab", ".strtab"],
  "security_features": {
    "nx_bit": true,
    "stack_canary": false,
    "pie": true,
    "relro": false,
    "fortify": false
  },
  "imports": ["strlen", "printf", "malloc"],
  "exports": ["main", "process_data"]
}
```

**Tool Used:** `pyelftools` library (pure Python, no external dependencies)

---

### 4. Vulnerability Scanning Module (`scan_for_vulnerabilities()`)

**Purpose:** Cross-reference identified software components against vulnerability databases.

#### **NVD Integration (`_scan_nvd()`)**

**Flow:**
```
1. Extract software components from firmware
   - Search config files for version strings
   - Pattern: software-name v1.2.3
   
2. Query NVD REST API v2.0:
   - Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
   - Params: keywordSearch="software_name"
   - Rate limit: 1 second between requests (per NVD policy)
   
3. Parse response CVEs:
   - Extract CVE ID (e.g., CVE-2024-1234)
   - Get description from vulnerability data
   - Match to affected files
   
4. Aggregate results:
   - Store in results['vulnerabilities']['nvd']
   - Track severity distribution (high/medium/low)
```

**Example Result:**
```json
{
  "id": "CVE-2024-1234",
  "description": "Buffer overflow in OpenSSL 1.0.2 allows remote code execution",
  "severity": "critical",
  "cvss_score": 9.8,
  "affected_files": ["lib/libssl.so.1.0.2"]
}
```

**Limitations:**
- Requires exact component name match
- API rate limiting (6 requests per 60 seconds in free tier)
- OSV and CVE CIRCL implementations are placeholder stubs
- No transitive dependency tracking (e.g., if openssl has vuln, anything using it is vulnerable)

---

### 5. Hash Calculation Module (`calculate_hashes()`)

**Purpose:** Create cryptographic fingerprints for integrity verification and deduplication.

**Implementation:**
```python
def calculate_hashes(self):
    """
    For each file in extracted_path:
    1. Read file content (binary mode)
    2. Compute MD5(content)   → weak, for reference only
    3. Compute SHA256(content) → strong, use for verification
    4. Record file size
    
    Output format:
    {
      "/path/to/file": {
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
        "size": 1024
      }
    }
    """
```

**Use Cases:**
- **Integrity checking:** Compare with vendor-provided checksums
- **Firmware versioning:** Same hash = same firmware version
- **Deduplication:** Identify identical files across firmware versions
- **Supply chain verification:** Detect tampered/modified firmware

---

### 6. Report Generation (`generate_report()`)

#### **JSON Report Structure**
```json
{
  "metadata": {
    "firmware_path": "/path/to/firmware.bin",
    "analysis_date": "2024-12-03 10:30:45",
    "analyzer_version": "2.0"
  },
  "extraction": {
    "success": true,
    "method": "unsquashfs -d ... firmware.bin",
    "file_type": "Squashfs filesystem"
  },
  "interesting_strings": {
    "/path/to/config": {
      "credentials": ["admin:password"],
      "network": ["192.168.1.1", "http://update-server.com"],
      "crypto": ["-----BEGIN RSA PRIVATE KEY-----"],
      "commands": ["/bin/telnetd", "/sbin/reboot"]
    }
  },
  "elf_analysis": [
    {
      "file": "/bin/httpd",
      "architecture": "ARM",
      "entry_point": "0x8048000",
      "file_type": "Executable",
      "security_features": {
        "nx_bit": true,
        "stack_canary": false,
        "pie": false,
        "relro": false,
        "fortify": false
      },
      "imports": ["strcpy", "printf"],
      "exports": []
    }
  ],
  "vulnerabilities": {
    "nvd": [
      {
        "id": "CVE-2024-1234",
        "description": "Buffer overflow...",
        "severity": "high",
        "cvss_score": 8.5,
        "affected_files": ["/lib/libc.so"]
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
    "/bin/httpd": {
      "md5": "...",
      "sha256": "...",
      "size": 45632
    }
  }
}
```

#### **PDF Report**
Uses `reportlab` to generate human-readable summary with:
- Title and metadata
- Vulnerability counts by severity
- Security findings organized by category
- File inventory
- Technical appendix

---

## Configuration System

```python
@dataclass
class AnalysisConfig:
    max_workers: int = 4           # Thread pool size for parallel analysis
    timeout: int = 300             # Subprocess timeout (seconds)
    enable_emulation: bool = False # (Placeholder) Run QEMU emulation
    enable_network_analysis: bool = False  # (Placeholder) pcap analysis
    enable_yara_scan: bool = True  # Pattern matching for malware signatures
    yara_rules_path: str = "rules.yar"    # Custom YARA rules file
    output_format: str = "json"    # Output: json, pdf, or both
```

---

## Execution Flow Diagram

```
main()
│
└─► parse CLI arguments
    │
    └─► FirmwareAnalyzer(firmware_path, config)
        │
        └─► run_analysis()
            │
            ├─► extract_firmware()          [Block until extraction complete]
            │   ├─ magic.from_file()        [File type detection]
            │   └─ subprocess.run()         [External tool: unsquashfs/binwalk]
            │
            ├─► analyze_strings()           [Parallel via ThreadPoolExecutor]
            │   ├─ _get_text_files()        [Find candidates]
            │   └─ [Thread 1..N] analyze_file_strings()
            │
            ├─► analyze_elf_files()         [Sequential, optional parallel]
            │   └─ _analyze_single_elf()
            │
            ├─► scan_for_vulnerabilities()  [Sequential with API calls]
            │   ├─ _identify_software_components()
            │   ├─ _scan_nvd()              [HTTP requests with rate limit]
            │   ├─ _scan_osv()              [Placeholder]
            │   └─ _scan_cve_circl()        [Placeholder]
            │
            ├─► calculate_hashes()          [Sequential hash computation]
            │
            ├─► generate_report()
            │   ├─ _generate_json_report()  [Write to reports/]
            │   └─ _generate_pdf_report()   [Write to reports/]
            │
            └─► return success/failure
                │
                └─► exit(0 or 1)
```

---

## Performance Considerations

### Memory Usage
- **Base:** ~100 MB
- **String analysis:** +File count × 1 MB buffer
- **Large firmware (>128 MB extracted):** ~2 GB total

### Optimization Strategies
```python
# ThreadPoolExecutor size tuning
workers = min(config.max_workers, cpu_count())

# Lazy loading of heavy modules
try:
    import angr  # Only imported if needed
except ImportError:
    logger.warning("angr not available, skipping advanced analysis")

# Timeout configuration
timeout = 300  # 5 minutes per extraction
# For large firmware:
timeout = 1200  # 20 minutes

# File read limiting
content = f.read()[:1024*1024]  # Only read first 1 MB per file
```

### Parallelization
- **String analysis:** Parallelized via ThreadPoolExecutor
- **ELF analysis:** Currently sequential (I/O bound, not CPU bound)
- **NVD scanning:** Sequential due to rate limiting (API constraint)

---

## Error Handling & Logging

**Logging Setup:**
```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firmware_analysis.log'),
        logging.StreamHandler()
    ]
)
```

**Output:**
- `firmware_analysis.log` — Full execution transcript
- `stdout` — Real-time progress messages
- `results['error']` — Captured error in JSON if analysis fails

**Error Recovery:**
- **Extraction fails:** Continue with best-effort extraction
- **ELF parsing fails on file X:** Log warning, skip file X, continue
- **NVD API timeout:** Log error, continue without that data
- **Timeout context:** Subprocess timeout handled gracefully

---

## Security Considerations

### What This Tool Can Audit
✅ Static code analysis (no execution)  
✅ Known vulnerability databases  
✅ Code patterns and hardcoded secrets  
✅ Binary security features  
✅ File integrity (hashes)

### What This Tool Cannot Detect
❌ Runtime behavior (would need emulation)  
❌ 0-day vulnerabilities (unknown exploits)  
❌ Encrypted code analysis (can't read encrypted binaries)  
❌ Side-channel attacks  
❌ Logic flaws (requires domain expertise)

### Limitations
- **False positives:** Regex matches may not be actual vulnerabilities
- **False negatives:** Sophisticated obfuscation bypasses detection
- **Incomplete scanning:** Only scans accessible files (not encrypted partitions)
- **Outdated databases:** NVD/OSV may lag behind latest disclosures

---

## Dependencies & Stack

### Core Python Libraries
| Package | Version | Purpose |
|---------|---------|---------|
| python-magic | ≥0.4.24 | File type detection via libmagic |
| yara-python | ≥4.2.0 | Pattern matching (malware signatures) |
| requests | ≥2.28.0 | HTTP requests for vulnerability APIs |
| pyelftools | ≥0.29 | ELF binary parsing (pure Python) |
| reportlab | ≥3.6.0 | PDF generation |

### Optional Libraries
| Package | Purpose |
|---------|---------|
| angr | Binary symbolic execution (advanced analysis) |
| capstone | Disassembly engine |
| scapy | Network packet analysis |
| scikit-learn | ML for anomaly detection |

### System Tools (Linux/Docker)
| Tool | Purpose |
|------|---------|
| binwalk | Generic firmware extraction |
| unsquashfs | SquashFS filesystem extraction |
| jefferson | JFFS2 extraction |
| ubireader | UBI extraction |
| libmagic | Binary file type detection |

---

## Future Enhancements (from nextsteps.md)

1. **Plugin Architecture:** Allow custom analyzer modules
2. **ML Component ID:** Neural network for version prediction
3. **Comparative Analysis:** Firmware version diffing
4. **CI/CD Integration:** GitHub Actions, GitLab CI
5. **Cloud Service:** SaaS platform with user accounts
6. **Firmware Database:** Crowdsourced firmware signatures
7. **Real-time Emulation:** QEMU-based dynamic analysis
8. **Integration Marketplace:** Slack, Jira, GitHub, PagerDuty connectors

---

## Conclusion

**Firmware Analyzer** is a comprehensive static analysis framework for IoT/embedded device security. It combines multiple analysis techniques (extraction, pattern matching, binary analysis, database lookups) into a unified pipeline, making firmware security assessment accessible and automatable.

**Key Strengths:**
- Modular architecture (easy to extend)
- Multi-threaded performance
- Cross-platform (with Docker)
- Comprehensive reporting

**Key Weaknesses:**
- Static-only (no execution)
- Database dependent (limited by NVD/OSV)
- Regex-based analysis (prone to false positives)
- No automated patching

For more information, see `README.md` and `GUIDE_NON_TECHNICAL.md`.
