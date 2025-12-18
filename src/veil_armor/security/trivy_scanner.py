"""
Trivy Security Scanner Integration for Veil Armor
Automated vulnerability scanning for dependencies and containers.
"""
import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class TrivyScanner:
    """
    Enterprise-grade security scanner using Trivy.
    Scans dependencies, containers, and infrastructure as code.
    """
    
    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path.cwd()
        self.reports_dir = self.project_root / "security_reports"
        self.reports_dir.mkdir(exist_ok=True)
        
    def check_trivy_installed(self) -> bool:
        """Check if Trivy is installed."""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def install_trivy_instructions(self) -> str:
        """Get installation instructions for Trivy."""
        return """
Trivy Installation Instructions:

Windows (PowerShell as Administrator):
    # Using Chocolatey
    choco install trivy
    
    # Or download binary
    Invoke-WebRequest -Uri https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Windows-64bit.zip -OutFile trivy.zip
    Expand-Archive -Path trivy.zip -DestinationPath C:\trivy
    $env:Path += ";C:\trivy"

Linux:
    # Debian/Ubuntu
    sudo apt-get install wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install trivy

macOS:
    brew install aquasecurity/trivy/trivy

After installation, verify with: trivy --version
"""
    
    def scan_dependencies(self, severity: str = "CRITICAL,HIGH") -> Dict:
        """
        Scan Python dependencies for vulnerabilities.
        
        Args:
            severity: Comma-separated list of severities (CRITICAL,HIGH,MEDIUM,LOW)
        
        Returns:
            Dictionary with scan results
        """
        if not self.check_trivy_installed():
            return {
                "status": "error",
                "message": "Trivy not installed",
                "instructions": self.install_trivy_instructions()
            }
        
        requirements_file = self.project_root / "requirements.txt"
        if not requirements_file.exists():
            return {
                "status": "error",
                "message": "requirements.txt not found"
            }
        
        output_file = self.reports_dir / f"trivy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            # Run Trivy scan
            cmd = [
                "trivy",
                "fs",
                "--security-checks", "vuln,config",
                "--severity", severity,
                "--format", "json",
                "--output", str(output_file),
                str(requirements_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse results
            if output_file.exists():
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                return {
                    "status": "success",
                    "report_file": str(output_file),
                    "scan_data": scan_data,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "status": "error",
                    "message": "Scan completed but no report generated",
                    "stderr": result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Scan timeout (exceeded 5 minutes)"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Scan failed: {str(e)}"
            }
    
    def scan_docker_image(self, image_name: str) -> Dict:
        """Scan Docker image for vulnerabilities."""
        if not self.check_trivy_installed():
            return {
                "status": "error",
                "message": "Trivy not installed"
            }
        
        output_file = self.reports_dir / f"docker_scan_{image_name.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            cmd = [
                "trivy",
                "image",
                "--severity", "CRITICAL,HIGH",
                "--format", "json",
                "--output", str(output_file),
                image_name
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                return {
                    "status": "success",
                    "report_file": str(output_file),
                    "scan_data": scan_data
                }
            else:
                return {
                    "status": "error",
                    "message": "Scan failed",
                    "stderr": result.stderr
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def generate_report(self, scan_results: Dict) -> str:
        """Generate human-readable report from scan results."""
        if scan_results.get("status") != "success":
            return f"Scan Error: {scan_results.get('message', 'Unknown error')}"
        
        report = []
        report.append("=" * 80)
        report.append("TRIVY SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {scan_results.get('timestamp', 'N/A')}")
        report.append(f"Report File: {scan_results.get('report_file', 'N/A')}")
        report.append("")
        
        scan_data = scan_results.get("scan_data", {})
        results = scan_data.get("Results", [])
        
        total_vulnerabilities = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get("Severity", "UNKNOWN")
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                elif severity == "LOW":
                    low_count += 1
        
        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Vulnerabilities: {total_vulnerabilities}")
        report.append(f"  CRITICAL: {critical_count}")
        report.append(f"  HIGH:     {high_count}")
        report.append(f"  MEDIUM:   {medium_count}")
        report.append(f"  LOW:      {low_count}")
        report.append("")
        
        if total_vulnerabilities > 0:
            report.append("VULNERABILITY DETAILS")
            report.append("-" * 80)
            
            for result in results:
                target = result.get("Target", "Unknown")
                vulnerabilities = result.get("Vulnerabilities", [])
                
                if vulnerabilities:
                    report.append(f"\nTarget: {target}")
                    
                    for vuln in vulnerabilities[:10]:  # Show top 10
                        vuln_id = vuln.get("VulnerabilityID", "N/A")
                        pkg_name = vuln.get("PkgName", "N/A")
                        installed_ver = vuln.get("InstalledVersion", "N/A")
                        fixed_ver = vuln.get("FixedVersion", "N/A")
                        severity = vuln.get("Severity", "N/A")
                        title = vuln.get("Title", "No description")
                        
                        report.append(f"\n  [{severity}] {vuln_id}")
                        report.append(f"    Package: {pkg_name}")
                        report.append(f"    Installed: {installed_ver}")
                        report.append(f"    Fixed: {fixed_ver}")
                        report.append(f"    Issue: {title[:60]}...")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def get_sbom(self) -> Dict:
        """Generate Software Bill of Materials (SBOM)."""
        if not self.check_trivy_installed():
            return {
                "status": "error",
                "message": "Trivy not installed"
            }
        
        output_file = self.reports_dir / f"sbom_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            cmd = [
                "trivy",
                "fs",
                "--format", "cyclonedx",
                "--output", str(output_file),
                str(self.project_root)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if output_file.exists():
                return {
                    "status": "success",
                    "sbom_file": str(output_file),
                    "message": "SBOM generated successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": "SBOM generation failed"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


def main():
    """Demo of Trivy scanner."""
    print("=" * 80)
    print("TRIVY SECURITY SCANNER - Veil Armor Integration")
    print("=" * 80)
    print()
    
    scanner = TrivyScanner()
    
    # Check if Trivy is installed
    print("Checking Trivy installation...")
    if scanner.check_trivy_installed():
        print("SUCCESS: Trivy is installed and ready")
        print()
        
        # Scan dependencies
        print("Scanning dependencies for vulnerabilities...")
        print("This may take a few minutes...")
        print("-" * 80)
        
        results = scanner.scan_dependencies(severity="CRITICAL,HIGH,MEDIUM")
        
        if results["status"] == "success":
            print("SCAN COMPLETED SUCCESSFULLY")
            print()
            report = scanner.generate_report(results)
            print(report)
            
            # Save report to file
            report_file = Path("security_reports") / "latest_report.txt"
            report_file.write_text(report)
            print(f"\nReport saved to: {report_file}")
            
        else:
            print(f"SCAN FAILED: {results.get('message', 'Unknown error')}")
    else:
        print("ERROR: Trivy is not installed")
        print()
        print(scanner.install_trivy_instructions())


if __name__ == "__main__":
    main()
