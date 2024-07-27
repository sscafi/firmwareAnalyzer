import subprocess
import os
import re
import json
import hashlib
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
import multiprocessing
import pkg_resources  # For pip packages

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.extracted_path = firmware_path + ".extracted"
        self.results = {}

    def extract_firmware(self):
        file_type = magic.from_file(self.firmware_path)
        if "SquashFS" in file_type:
            subprocess.run(['unsquashfs', self.firmware_path])
        elif "JFFS2" in file_type:
            subprocess.run(['jefferson', self.firmware_path])
        elif "UBI" in file_type:
            subprocess.run(['ubireader_extract_files', self.firmware_path])
        else:
            subprocess.run(['binwalk', '-e', self.firmware_path])

    def analyze_strings(self):
        interesting_patterns = [
            r'password', r'admin', r'key=', r'https?://', r'secret',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',  # IPv4
        ]
        
        self.results['interesting_strings'] = []
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        for pattern in interesting_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.results['interesting_strings'].append({
                                    'file': file_path,
                                    'pattern': pattern,
                                    'matches': matches
                                })
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    def check_file_types(self):
        self.results['file_types'] = {}
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_type = magic.from_file(file_path)
                if file_type not in self.results['file_types']:
                    self.results['file_types'][file_type] = []
                self.results['file_types'][file_type].append(file_path)

    def analyze_elf_files(self):
        self.results['elf_analysis'] = []
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                if magic.from_file(file_path, mime=True) == 'application/x-executable':
                    try:
                        with open(file_path, 'rb') as f:
                            elf = ELFFile(f)
                            self.results['elf_analysis'].append({
                                'file': file_path,
                                'architecture': elf.get_machine_arch(),
                                'entry_point': hex(elf.header.e_entry),
                                'sections': [s.name for s in elf.iter_sections()],
                                'symbols': [s.name for s in elf.get_section_by_name('.symtab').iter_symbols()] if elf.get_section_by_name('.symtab') else []
                            })
                    except Exception as e:
                        print(f"Error analyzing ELF file {file_path}: {e}")

    def scan_for_vulnerabilities(self):
        # Get installed packages
        installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
        
        # Collect vulnerabilities from different databases
        vulnerabilities = []

        # Scan NVD
        vulnerabilities.extend(self.scan_nvd())
        
        # Scan OSV
        vulnerabilities.extend(self.scan_osv())
        
        # Scan CVE (if applicable, otherwise leave as is)
        vulnerabilities.extend(self.scan_cve())

        # Check installed packages against vulnerabilities
        for vulnerability in vulnerabilities:
            affected_packages = [pkg for pkg in installed_packages if pkg in vulnerability['description']]
            if affected_packages:
                print(f"Vulnerability ID: {vulnerability['id']}")
                print(f"Description: {vulnerability['description']}")
                print(f"Affected Packages: {', '.join(affected_packages)}")

    
    def scan_osv(self):
        vulnerabilities = []
        url = "https://osv-api.endpoints.dev/v1/vulns"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulns', []):
                    package_name = vuln['package']['name']
                    affected_versions = ", ".join(affected['version'] for affected in vuln['affected'])
                    vulnerabilities.append({'id': package_name, 'description': f"Affected: {affected_versions}"})
            else:
                print("Failed to fetch data from OSV.")
        except Exception as e:
            print(f"Error while fetching OSV data: {e}")

        return vulnerabilities
    
    def scan_cve(self):
        vulnerabilities = []
        # Base URL for the CVE Search API
        base_url = "https://cve.circl.lu/api"

        try:
            # Example: Get CVEs for all packages. You can modify the endpoint to narrow it down.
            for pkg in pkg_resources.working_set:  # Iterate over installed packages
                package_name = pkg.key
                response = requests.get(f"{base_url}/search/{package_name}")
                
                if response.status_code == 200:
                    cve_data = response.json()
                    for item in cve_data:
                        cve_id = item.get('id', 'N/A')
                        description = item.get('summary', 'No description available.')
                        vulnerabilities.append({'id': cve_id, 'description': description})
                else:
                    print(f"Failed to fetch data for package: {package_name}")

        except Exception as e:
            print(f"Error while fetching CVE data: {e}")

        return vulnerabilities


   

    def yara_scan(self):
        # Compile YARA rules (you'd need to create these rules)
        rules = yara.compile(filepath='path/to/your/yara/rules.yar')
        
        self.results['yara_matches'] = []
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                matches = rules.match(file_path)
                if matches:
                    self.results['yara_matches'].append({
                        'file': file_path,
                        'rules': [match.rule for match in matches]
                    })

    def check_certificates(self):
        self.results['certificates'] = []
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.crt') or file.endswith('.pem'):
                    # Here you'd parse and analyze the certificate
                    # For brevity, we're just noting its existence
                    self.results['certificates'].append(file_path)

    def analyze_configs(self):
        # Look for common configuration files
        config_patterns = ['*.conf', '*.cfg', '*.ini', '*.json', '*.xml']
        self.results['config_files'] = []
        for pattern in config_patterns:
            self.results['config_files'].extend(
                [os.path.join(root, file) 
                 for root, dirs, files in os.walk(self.extracted_path)
                 for file in files if file.endswith(pattern[1:])]
            )

    def check_for_backdoors(self):
        # This is a complex task that often requires manual analysis
        # Here we're just looking for some suspicious patterns
        backdoor_patterns = [
            r'backdoor', r'remote_access', r'hidden_user',
            r'nc -l', r'netcat', r'reverse shell'
        ]
        self.results['potential_backdoors'] = []
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        for pattern in backdoor_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self.results['potential_backdoors'].append({
                                    'file': file_path,
                                    'pattern': pattern
                                })
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    def calculate_hashes(self):
        self.results['file_hashes'] = {}
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    content = f.read()
                    self.results['file_hashes'][file_path] = {
                        'md5': hashlib.md5(content).hexdigest(),
                        'sha256': hashlib.sha256(content).hexdigest()
                    }

    def run_analysis(self):
        self.extract_firmware()
        self.analyze_strings()
        self.check_file_types()
        self.analyze_elf_files()
        self.scan_for_vulnerabilities()
        self.yara_scan()
        self.check_certificates()
        self.analyze_configs()
        self.check_for_backdoors()
        self.calculate_hashes()
        self.check_nvd_vulnerabilities()
        self.perform_control_flow_analysis()
        self. extract_firmware()
        self.emulate_firmware()
        self.analyze_network_traffic()
        self.detect_anomalies()
        self.generate_pdf_report()
        self.analyze_file()

        # Save results to a JSON file
        with open('analysis_results.json', 'w') as f:
            json.dump(self.results, f, indent=4)

        print("Analysis complete. Results saved to analysis_results.json")



    def detect_anomalies(self):
        # Extract features from firmware (this is highly dependent on your specific use case)
        features = self.extract_features()
        
        # Train the model (in practice, you'd train on a large dataset of known good firmware)
        clf = IsolationForest(contamination=0.1, random_state=42)
        clf.fit(features)
        
        # Predict anomalies
        anomalies = clf.predict(features)
        self.results['anomalies'] = anomalies.tolist()  

    def check_nvd_vulnerabilities(self):
        self.results['nvd_vulnerabilities'] = []
        api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        
        # You'd need to identify software/versions in the firmware
        # This is a simplified example
        for software, version in self.identified_software.items():
            params = {
                "keyword": f"{software} {version}",
                "resultsPerPage": 100
            }
            response = requests.get(api_url, params=params)
            if response.status_code == 200:
                vulns = response.json()['result']['CVE_Items']
                self.results['nvd_vulnerabilities'].extend(vulns)
    

    def perform_control_flow_analysis(self, binary_path):
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()
        
        # Analyze the control flow graph
        for node in cfg.graph.nodes():
            # Perform analysis on each node
            pass
        
        # You can identify interesting patterns, potential vulnerabilities, etc.

    
    
    def analyze_file(file_path):
        # Perform analysis on a single file
        pass
    
    def parallel_analysis(self):
        with multiprocessing.Pool() as pool:
            files = [os.path.join(root, file) for root, dirs, files in os.walk(self.extracted_path) for file in files]
            results = pool.map(analyze_file, files)
        self.results['parallel_analysis'] = results

    def generate_pdf_report(self):
        c = canvas.Canvas("firmware_analysis_report.pdf", pagesize=letter)
        width, height = letter
        
        # Add content to the PDF
        c.drawString(100, height - 100, "Firmware Analysis Report")
        y = height - 120
        for key, value in self.results.items():
            y -= 20
            c.drawString(100, y, f"{key}: {value}")
        
        c.save()
    
    def analyze_network_traffic(self):
        # Start packet capture (assuming emulation is running)
        packets = sniff(iface="tap0", count=1000)
        
        # Analyze packets
        for packet in packets:
            if TCP in packet:
                # Analyze TCP traffic
                pass
            elif UDP in packet:
                # Analyze UDP traffic
                pass
            # Add more protocol analyses as needed
        
    def emulate_firmware(self):
        # Assuming we've identified the architecture and created a rootfs
        qemu_cmd = [
            'qemu-system-arm',
            '-M', 'virt',
            '-kernel', 'path/to/extracted/kernel',
            '-initrd', 'path/to/extracted/initrd',
            '-append', 'root=/dev/ram rw console=ttyAMA0',
            '-nographic'
        ]
        process = subprocess.Popen(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Interact with the emulated system, analyze behavior, etc.

if __name__ == "__main__":
    firmware_path = "path/to/your/firmware.bin"
    analyzer = FirmwareAnalyzer(firmware_path)
    analyzer.run_analysis()