"""
Real Trivy security scanner test - actual vulnerability scanning.
"""
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime
import shutil


def check_trivy_installed() -> bool:
    """Check if Trivy is installed."""
    print("=" * 80)
    print("TRIVY INSTALLATION CHECK")
    print("=" * 80)
    print()
    
    try:
        result = subprocess.run(
            ["trivy", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            version_line = result.stdout.strip().split('\n')[0]
            print(f"✓ Trivy is installed: {version_line}")
            return True
        else:
            print("X Trivy command failed")
            return False
            
    except FileNotFoundError:
        print("X Trivy is not installed")
        print()
        print("Installation instructions:")
        print()
        print("Windows (Chocolatey):")
        print("  choco install trivy")
        print()
        print("Windows (Manual):")
        print("  Download from: https://github.com/aquasecurity/trivy/releases")
        print("  Extract and add to PATH")
        print()
        print("Linux:")
        print("  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -")
        print("  echo 'deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main' | sudo tee -a /etc/apt/sources.list.d/trivy.list")
        print("  sudo apt-get update && sudo apt-get install trivy")
        print()
        print("macOS (Homebrew):")
        print("  brew install trivy")
        return False
        
    except Exception as e:
        print(f"X Error checking Trivy: {str(e)}")
        return False


def scan_dependencies() -> dict:
    """Scan Python dependencies for vulnerabilities."""
    print()
    print("=" * 80)
    print("SCANNING DEPENDENCIES FOR VULNERABILITIES")
    print("=" * 80)
    print()
    
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("X requirements.txt not found")
        return {"error": "requirements.txt not found"}
    
    print(f"Scanning: {requirements_file.absolute()}")
    print("This may take a few minutes...")
    print()
    
    try:
        # Run Trivy scan
        result = subprocess.run(
            [
                "trivy", "fs",
                "--scanners", "vuln",
                "--severity", "HIGH,CRITICAL",
                "--format", "json",
                str(requirements_file)
            ],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes
        )
        
        if result.returncode != 0:
            print(f"X Trivy scan failed (exit code: {result.returncode})")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return {"error": result.stderr}
        
        # Parse JSON output
        scan_data = json.loads(result.stdout)
        
        # Count vulnerabilities
        vuln_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        packages_with_vulns = []
        
        for scan_result in scan_data.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                vuln_count[severity] = vuln_count.get(severity, 0) + 1
                
                pkg_name = vuln.get("PkgName", "unknown")
                vuln_id = vuln.get("VulnerabilityID", "unknown")
                
                packages_with_vulns.append({
                    "package": pkg_name,
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", "not available"),
                    "vulnerability_id": vuln_id,
                    "severity": severity,
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", "")[:200]
                })
        
        # Print results
        print("SCAN RESULTS:")
        print("-" * 80)
        print(f"Critical:  {vuln_count.get('CRITICAL', 0)}")
        print(f"High:      {vuln_count.get('HIGH', 0)}")
        print(f"Medium:    {vuln_count.get('MEDIUM', 0)}")
        print(f"Low:       {vuln_count.get('LOW', 0)}")
        print(f"Total:     {sum(vuln_count.values())}")
        print()
        
        if packages_with_vulns:
            print("VULNERABLE PACKAGES:")
            print("-" * 80)
            
            # Show top 10 most critical
            critical_first = sorted(
                packages_with_vulns,
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4)
            )
            
            for i, vuln in enumerate(critical_first[:10], 1):
                print(f"\n{i}. {vuln['package']} ({vuln['installed_version']})")
                print(f"   Vulnerability: {vuln['vulnerability_id']}")
                print(f"   Severity: {vuln['severity']}")
                print(f"   Fixed in: {vuln['fixed_version']}")
                if vuln['title']:
                    print(f"   Title: {vuln['title']}")
            
            if len(critical_first) > 10:
                print(f"\n... and {len(critical_first) - 10} more vulnerabilities")
        else:
            print("✓ No vulnerabilities found!")
        
        return {
            "vulnerability_count": vuln_count,
            "packages": packages_with_vulns,
            "total": sum(vuln_count.values())
        }
        
    except subprocess.TimeoutExpired:
        print("X Trivy scan timed out")
        return {"error": "Scan timed out"}
        
    except json.JSONDecodeError as e:
        print(f"X Failed to parse Trivy output: {str(e)}")
        return {"error": "Invalid JSON output"}
        
    except Exception as e:
        print(f"X Scan error: {str(e)}")
        return {"error": str(e)}


def generate_sbom() -> bool:
    """Generate Software Bill of Materials (SBOM)."""
    print()
    print("=" * 80)
    print("GENERATING SOFTWARE BILL OF MATERIALS (SBOM)")
    print("=" * 80)
    print()
    
    try:
        output_file = "sbom.json"
        
        print(f"Generating SBOM in CycloneDX format...")
        print(f"Output: {output_file}")
        print()
        
        result = subprocess.run(
            [
                "trivy", "fs",
                "--format", "cyclonedx",
                "--output", output_file,
                "."
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            output_path = Path(output_file)
            if output_path.exists():
                size = output_path.stat().st_size
                print(f"✓ SBOM generated successfully")
                print(f"  File: {output_path.absolute()}")
                print(f"  Size: {size:,} bytes")
                
                # Parse and show summary
                with open(output_file, 'r') as f:
                    sbom_data = json.load(f)
                
                components = sbom_data.get("components", [])
                print(f"  Components: {len(components)}")
                
                return True
            else:
                print("X SBOM file not created")
                return False
        else:
            print(f"X SBOM generation failed")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"X SBOM generation error: {str(e)}")
        return False


def save_report(scan_results: dict):
    """Save scan report to file."""
    print()
    print("=" * 80)
    print("SAVING SCAN REPORT")
    print("=" * 80)
    print()
    
    report_dir = Path("security_reports")
    report_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = report_dir / f"trivy_scan_{timestamp}.json"
    
    report = {
        "scan_date": datetime.now().isoformat(),
        "scanner": "Trivy",
        "results": scan_results
    }
    
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Report saved: {report_file.absolute()}")
        print(f"  Size: {report_file.stat().st_size:,} bytes")
        
    except Exception as e:
        print(f"X Failed to save report: {str(e)}")


def main():
    """Run real Trivy security tests."""
    print()
    print("=" * 80)
    print("MODAL ARMOR - TRIVY SECURITY SCANNER TEST")
    print("Real vulnerability scanning and SBOM generation")
    print("=" * 80)
    print()
    
    # Check if Trivy is installed
    if not check_trivy_installed():
        print()
        print("=" * 80)
        print("TRIVY NOT INSTALLED")
        print("=" * 80)
        print()
        print("Please install Trivy to continue.")
        print("After installation, run this script again.")
        sys.exit(1)
    
    # Scan dependencies
    scan_results = scan_dependencies()
    
    # Generate SBOM
    sbom_success = generate_sbom()
    
    # Save report
    if not scan_results.get("error"):
        save_report(scan_results)
    
    # Final summary
    print()
    print("=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
    print()
    
    total_vulns = scan_results.get("total", 0)
    
    if total_vulns == 0:
        print("✓ No vulnerabilities detected")
        print("✓ All dependencies are secure")
    else:
        print(f"⚠ {total_vulns} vulnerabilities detected")
        
        critical = scan_results.get("vulnerability_count", {}).get("CRITICAL", 0)
        high = scan_results.get("vulnerability_count", {}).get("HIGH", 0)
        
        if critical > 0:
            print(f"⚠ {critical} CRITICAL vulnerabilities require immediate attention")
        if high > 0:
            print(f"⚠ {high} HIGH vulnerabilities should be addressed soon")
    
    if sbom_success:
        print("✓ SBOM generated successfully")
    
    print()
    print("=" * 80)
    print()


if __name__ == "__main__":
    main()
