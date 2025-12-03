import subprocess
import os
import re
import json
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import concurrent.futures
from contextlib import contextmanager

try:
    import magic
    import yara
    import requests
    from elftools.elf.elffile import ELFFile
    from capstone import *
    import angr
    from scapy.all import *
    from sklearn.ensemble import IsolationForest
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
except ImportError as e:
    print(f"Warning: Some optional dependencies are missing: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firmware_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisConfig:
    """Configuration for firmware analysis"""
    max_workers: int = 4
    timeout: int = 300
    enable_emulation: bool = False
    enable_network_analysis: bool = False
    enable_yara_scan: bool = True
    yara_rules_path: str = "rules.yar"
    output_format: str = "json"  # json, pdf, both

@dataclass
class VulnerabilityInfo:
    """Structure for vulnerability information"""
    id: str
    description: str
    severity: str = "unknown"
    cvss_score: float = 0.0
    affected_files: List[str] = None

    def __post_init__(self):
        if self.affected_files is None:
            self.affected_files = []

class FirmwareAnalyzer:
    def __init__(self, firmware_path: str, config: AnalysisConfig = None):
        self.firmware_path = Path(firmware_path)
        self.config = config or AnalysisConfig()
        self.extracted_path = self.firmware_path.parent / f"{self.firmware_path.name}.extracted"
        self.results = {
            'metadata': {
                'firmware_path': str(self.firmware_path),
                'analysis_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'analyzer_version': '2.0'
            }
        }
        self.identified_software = {}
        
        # Ensure output directories exist
        os.makedirs("reports", exist_ok=True)
        os.makedirs("logs", exist_ok=True)

    @contextmanager
    def _timeout_context(self, seconds: int):
        """Context manager for timeouts"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Operation timed out after {seconds} seconds")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)

    def _safe_decode(self, data: bytes, encodings: List[str] = None) -> str:
        """Safely decode bytes with multiple encoding attempts"""
        if encodings is None:
            encodings = ['utf-8', 'latin1', 'ascii', 'cp1252']
        
        for encoding in encodings:
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # If all fail, decode with errors='ignore'
        return data.decode('utf-8', errors='ignore')

    def extract_firmware(self) -> bool:
        """Enhanced firmware extraction with better error handling"""
        logger.info(f"Extracting firmware: {self.firmware_path}")
        
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {self.firmware_path}")

        try:
            file_type = magic.from_file(str(self.firmware_path))
            logger.info(f"Detected file type: {file_type}")
            
            extraction_commands = {
                "SquashFS": ['unsquashfs', '-d', str(self.extracted_path), str(self.firmware_path)],
                "JFFS2": ['jefferson', '-d', str(self.extracted_path), str(self.firmware_path)],
                "UBI": ['ubireader_extract_files', '-o', str(self.extracted_path), str(self.firmware_path)],
                "Zip": ['unzip', '-d', str(self.extracted_path), str(self.firmware_path)],
                "7-zip": ['7z', 'x', str(self.firmware_path), f'-o{self.extracted_path}']
            }
            
            command_used = None
            for fs_type, cmd in extraction_commands.items():
                if fs_type.lower() in file_type.lower():
                    command_used = cmd
                    break
            
            if not command_used:
                # Fallback to binwalk
                command_used = ['binwalk', '-e', '-M', '-C', str(self.extracted_path.parent), str(self.firmware_path)]
            
            # Use subprocess timeout (cross-platform) instead of signal.SIGALRM
            try:
                result = subprocess.run(
                    command_used,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=self.config.timeout
                )
            except subprocess.TimeoutExpired as e:
                logger.error(f"Extraction timed out: {e}")
                self.results['extraction'] = {
                    'success': False,
                    'error': f'Timeout after {self.config.timeout} seconds'
                }
                return False
            
            self.results['extraction'] = {
                'success': True,
                'method': ' '.join(command_used),
                'file_type': file_type
            }
            logger.info("Firmware extraction completed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Extraction failed: {e}")
            self.results['extraction'] = {
                'success': False,
                'error': str(e),
                'stderr': e.stderr
            }
            return False
        except Exception as e:
            logger.error(f"Unexpected error during extraction: {e}")
            self.results['extraction'] = {'success': False, 'error': str(e)}
            return False

    def analyze_strings(self) -> None:
        """Enhanced string analysis with categorized patterns"""
        logger.info("Analyzing interesting strings")
        
        pattern_categories = {
            'credentials': [
                r'password\s*[:=]\s*[^\s\n]+',
                r'admin\s*[:=]\s*[^\s\n]+',
                r'root\s*[:=]\s*[^\s\n]+',
                r'key\s*[:=]\s*[^\s\n]+',
                r'secret\s*[:=]\s*[^\s\n]+',
                r'token\s*[:=]\s*[^\s\n]+'
            ],
            'network': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
                r'https?://[^\s\n]+',  # URLs
                r'ftp://[^\s\n]+',
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
                r':[0-9]{1,5}\b'  # Ports
            ],
            'crypto': [
                r'-----BEGIN [A-Z ]+-----',
                r'-----END [A-Z ]+-----',
                r'[A-Fa-f0-9]{32,}',  # Long hex strings (potential keys)
                r'ssh-rsa [A-Za-z0-9+/=]+',
                r'ssh-dss [A-Za-z0-9+/=]+'
            ],
            'commands': [
                r'/bin/[a-zA-Z0-9_-]+',
                r'/usr/bin/[a-zA-Z0-9_-]+',
                r'/sbin/[a-zA-Z0-9_-]+',
                r'sudo [a-zA-Z0-9_-]+',
                r'chmod [0-9]+ [^\s\n]+',
                r'chown [a-zA-Z0-9_:-]+ [^\s\n]+'
            ]
        }
        
        self.results['interesting_strings'] = {}
        
        def analyze_file_strings(file_path: Path) -> Dict:
            file_results = {}
            try:
                with open(file_path, 'rb') as f:
                    content = self._safe_decode(f.read()[:1024*1024])  # Limit to 1MB
                    
                for category, patterns in pattern_categories.items():
                    matches = []
                    for pattern in patterns:
                        found = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                        if found:
                            matches.extend(found)
                    
                    if matches:
                        file_results[category] = list(set(matches))  # Remove duplicates
                        
            except Exception as e:
                logger.warning(f"Error analyzing strings in {file_path}: {e}")
                
            return file_results
        
        # Use thread pool for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_file = {}
            
            for file_path in self._get_text_files():
                future = executor.submit(analyze_file_strings, file_path)
                future_to_file[future] = str(file_path)
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        self.results['interesting_strings'][file_path] = result
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")

    def _get_text_files(self) -> List[Path]:
        """Get list of text files for analysis"""
        text_extensions = {'.txt', '.conf', '.cfg', '.ini', '.json', '.xml', '.sh', '.py', '.c', '.h', '.cpp'}
        text_files = []
        
        for file_path in self.extracted_path.rglob('*'):
            if file_path.is_file():
                if file_path.suffix.lower() in text_extensions:
                    text_files.append(file_path)
                elif file_path.stat().st_size < 1024*1024:  # Check small files
                    try:
                        file_type = magic.from_file(str(file_path), mime=True)
                        if 'text' in file_type:
                            text_files.append(file_path)
                    except:
                        pass
        
        return text_files

    def analyze_elf_files(self) -> None:
        """Enhanced ELF analysis with security checks"""
        logger.info("Analyzing ELF files")
        self.results['elf_analysis'] = []
        
        for file_path in self.extracted_path.rglob('*'):
            if not file_path.is_file():
                continue
                
            try:
                file_type = magic.from_file(str(file_path), mime=True)
                if 'application/x-executable' in file_type or 'application/x-sharedlib' in file_type:
                    elf_info = self._analyze_single_elf(file_path)
                    if elf_info:
                        self.results['elf_analysis'].append(elf_info)
            except Exception as e:
                logger.warning(f"Error checking file type for {file_path}: {e}")

    def _analyze_single_elf(self, file_path: Path) -> Optional[Dict]:
        """Analyze a single ELF file"""
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Security analysis
                security_features = {
                    'nx_bit': False,
                    'stack_canary': False,
                    'pie': False,
                    'relro': False,
                    'fortify': False
                }
                
                # Check for security features
                for section in elf.iter_sections():
                    if section.name == '.note.GNU-stack':
                        # Check NX bit
                        if section['sh_flags'] & 0x1 == 0:  # Not executable
                            security_features['nx_bit'] = True
                
                # Check for symbols indicating security features
                try:
                    symbol_table = elf.get_section_by_name('.symtab')
                    if symbol_table:
                        for symbol in symbol_table.iter_symbols():
                            symbol_name = symbol.name
                            if '__stack_chk_fail' in symbol_name:
                                security_features['stack_canary'] = True
                            elif '_FORTIFY_SOURCE' in symbol_name:
                                security_features['fortify'] = True
                except:
                    pass
                
                return {
                    'file': str(file_path),
                    'architecture': elf.get_machine_arch(),
                    'entry_point': hex(elf.header.e_entry),
                    'file_type': self._get_elf_type(elf.header.e_type),
                    'sections': [s.name for s in elf.iter_sections() if s.name],
                    'security_features': security_features,
                    'imports': self._get_elf_imports(elf),
                    'exports': self._get_elf_exports(elf)
                }
                
        except Exception as e:
            logger.warning(f"Error analyzing ELF file {file_path}: {e}")
            return None

    def _get_elf_type(self, e_type: int) -> str:
        """Get human-readable ELF type"""
        types = {
            1: 'Relocatable',
            2: 'Executable',
            3: 'Shared Object',
            4: 'Core'
        }
        return types.get(e_type, f'Unknown ({e_type})')

    def _get_elf_imports(self, elf: ELFFile) -> List[str]:
        """Get imported functions"""
        imports = []
        try:
            dynamic_section = elf.get_section_by_name('.dynsym')
            if dynamic_section:
                for symbol in dynamic_section.iter_symbols():
                    if symbol['st_shndx'] == 'SHN_UNDEF' and symbol.name:
                        imports.append(symbol.name)
        except:
            pass
        return imports

    def _get_elf_exports(self, elf: ELFFile) -> List[str]:
        """Get exported functions"""
        exports = []
        try:
            symbol_section = elf.get_section_by_name('.symtab')
            if symbol_section:
                for symbol in symbol_section.iter_symbols():
                    if symbol['st_shndx'] != 'SHN_UNDEF' and symbol.name and symbol['st_info']['bind'] == 'STB_GLOBAL':
                        exports.append(symbol.name)
        except:
            pass
        return exports

    def scan_for_vulnerabilities(self) -> None:
        """Enhanced vulnerability scanning with multiple sources"""
        logger.info("Scanning for vulnerabilities")
        self.results['vulnerabilities'] = {
            'nvd': [],
            'osv': [],
            'cve': [],
            'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        # First, identify software components
        self._identify_software_components()
        
        # Scan different databases
        try:
            self._scan_nvd()
            self._scan_osv()
            self._scan_cve_circl()
        except Exception as e:
            logger.error(f"Error during vulnerability scanning: {e}")

    def _identify_software_components(self) -> None:
        """Identify software components and versions"""
        logger.info("Identifying software components")
        
        # Look for version strings in binaries and config files
        version_patterns = [
            r'([a-zA-Z0-9_-]+)\s+v?(\d+\.\d+[\.\d]*)',
            r'version[:\s]+(["\']?)(\d+\.\d+[\.\d]*)\1',
            r'([a-zA-Z0-9_-]+)-(\d+\.\d+[\.\d]*)',
        ]
        
        for file_path in self._get_text_files():
            try:
                with open(file_path, 'rb') as f:
                    content = self._safe_decode(f.read())
                    
                for pattern in version_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple) and len(match) >= 2:
                            software = match[0] if len(match[0]) > 2 else match[1]
                            version = match[1] if len(match[0]) > 2 else match[0]
                            if software and version:
                                self.identified_software[software.lower()] = version
            except Exception as e:
                logger.warning(f"Error identifying software in {file_path}: {e}")

    def _scan_nvd(self) -> None:
        """Scan NVD database"""
        if not self.identified_software:
            return
            
        logger.info("Scanning NVD database")
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        for software, version in list(self.identified_software.items())[:5]:  # Limit requests
            try:
                params = {
                    "keywordSearch": f"{software}",
                    "resultsPerPage": 20
                }
                
                response = requests.get(api_url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if 'vulnerabilities' in data:
                        for vuln in data['vulnerabilities'][:10]:  # Limit results
                            cve_data = vuln.get('cve', {})
                            vuln_info = VulnerabilityInfo(
                                id=cve_data.get('id', 'Unknown'),
                                description=cve_data.get('descriptions', [{}])[0].get('value', 'No description'),
                                severity='medium',  # Would need more parsing for actual severity
                                affected_files=[software]
                            )
                            self.results['vulnerabilities']['nvd'].append(asdict(vuln_info))
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.warning(f"Error scanning NVD for {software}: {e}")

    def _scan_osv(self) -> None:
        """Scan OSV database"""
        logger.info("Scanning OSV database")
        # OSV implementation would go here
        pass

    def _scan_cve_circl(self) -> None:
        """Scan CVE CIRCL database"""
        logger.info("Scanning CVE CIRCL database")
        # CVE CIRCL implementation would go here
        pass

    def calculate_hashes(self) -> None:
        """Calculate file hashes with progress tracking"""
        logger.info("Calculating file hashes")
        self.results['file_hashes'] = {}
        
        files_to_hash = list(self.extracted_path.rglob('*'))
        files_to_hash = [f for f in files_to_hash if f.is_file()]
        
        for i, file_path in enumerate(files_to_hash):
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    self.results['file_hashes'][str(file_path)] = {
                        'md5': hashlib.md5(content).hexdigest(),
                        'sha256': hashlib.sha256(content).hexdigest(),
                        'size': len(content)
                    }
                
                if i % 100 == 0:
                    logger.info(f"Hashed {i}/{len(files_to_hash)} files")
                    
            except Exception as e:
                logger.warning(f"Error hashing {file_path}: {e}")

    def generate_report(self) -> None:
        """Generate analysis report in specified format"""
        logger.info("Generating analysis report")
        
        if self.config.output_format in ['json', 'both']:
            self._generate_json_report()
        
        if self.config.output_format in ['pdf', 'both']:
            self._generate_pdf_report()

    def _generate_json_report(self) -> None:
        """Generate JSON report"""
        report_path = Path("reports") / f"analysis_report_{int(time.time())}.json"
        
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to: {report_path}")

    def _generate_pdf_report(self) -> None:
        """Generate PDF report"""
        report_path = Path("reports") / f"analysis_report_{int(time.time())}.pdf"
        
        doc = SimpleDocTemplate(str(report_path), pagesize=letter)
        styles = getSampleStyleSheet()
        content = []
        
        # Title
        title = Paragraph("Firmware Analysis Report", styles['Title'])
        content.append(title)
        content.append(Spacer(1, 12))
        
        # Metadata
        metadata_text = f"""
        <b>Firmware Path:</b> {self.results['metadata']['firmware_path']}<br/>
        <b>Analysis Date:</b> {self.results['metadata']['analysis_date']}<br/>
        <b>Analyzer Version:</b> {self.results['metadata']['analyzer_version']}
        """
        content.append(Paragraph(metadata_text, styles['Normal']))
        content.append(Spacer(1, 12))
        
        # Summary sections
        for section, data in self.results.items():
            if section == 'metadata':
                continue
                
            section_title = Paragraph(f"<b>{section.replace('_', ' ').title()}</b>", styles['Heading2'])
            content.append(section_title)
            
            if isinstance(data, dict) and data:
                summary = f"Found {len(data)} items in this category."
            elif isinstance(data, list) and data:
                summary = f"Found {len(data)} items in this category."
            else:
                summary = "No items found in this category."
            
            content.append(Paragraph(summary, styles['Normal']))
            content.append(Spacer(1, 6))
        
        doc.build(content)
        logger.info(f"PDF report saved to: {report_path}")

    def run_analysis(self) -> bool:
        """Run complete firmware analysis"""
        logger.info(f"Starting firmware analysis: {self.firmware_path}")
        
        try:
            # Core analysis steps
            if not self.extract_firmware():
                logger.error("Firmware extraction failed - aborting analysis")
                return False
            
            self.analyze_strings()
            self.analyze_elf_files()
            self.scan_for_vulnerabilities()
            self.calculate_hashes()
            
            # Generate report
            self.generate_report()
            
            logger.info("Analysis completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Analysis failed with error: {e}")
            self.results['error'] = str(e)
            return False

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Firmware Analyzer")
    parser.add_argument("firmware_path", help="Path to firmware file")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--format", choices=['json', 'pdf', 'both'], default='json', help="Output format")
    
    args = parser.parse_args()
    
    config = AnalysisConfig(
        max_workers=args.workers,
        timeout=args.timeout,
        output_format=args.format
    )
    
    analyzer = FirmwareAnalyzer(args.firmware_path, config)
    success = analyzer.run_analysis()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
