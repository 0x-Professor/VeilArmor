#!/usr/bin/env python3
"""
VeilArmor v2.0 - Command Line Interface

Provides CLI commands for managing and interacting with VeilArmor.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def colored(text: str, color: str) -> str:
    """Apply color to text."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def print_banner():
    """Print VeilArmor banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██╗   ██╗███████╗██╗██╗      █████╗ ██████╗ ███╗   ███╗ ██████╗██████╗  ║
║   ██║   ██║██╔════╝██║██║     ██╔══██╗██╔══██╗████╗ ████║██╔═══██╗██╔══██╗ ║
║   ██║   ██║█████╗  ██║██║     ███████║██████╔╝██╔████╔██║██║   ██║██████╔╝ ║
║   ╚██╗ ██╔╝██╔══╝  ██║██║     ██╔══██║██╔══██╗██║╚██╔╝██║██║   ██║██╔══██╗ ║
║    ╚████╔╝ ███████╗██║███████╗██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║ ║
║     ╚═══╝  ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ║
║                                                                   ║
║                 Enterprise LLM Security Framework v2.0            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(colored(banner, "cyan"))


# ---------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------

def cmd_serve(args):
    """Start the VeilArmor server."""
    import uvicorn
    from src.core.config import get_settings
    
    settings = get_settings()
    
    print(colored(f"Starting VeilArmor server on {args.host}:{args.port}", "green"))
    
    uvicorn.run(
        "src.api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
        log_level=args.log_level,
    )


def cmd_classify(args):
    """Classify text for threats."""
    from src.classifier import ThreatClassifier
    from src.core.config import get_settings
    
    settings = get_settings()
    classifier = ThreatClassifier(settings)
    
    # Get text from args or stdin
    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    
    result = classifier.classify(text)
    
    if args.json:
        output = {
            "threats": result.threats,
            "severity": result.severity,
            "confidence": result.confidence,
            "details": result.details,
        }
        print(json.dumps(output, indent=2))
    else:
        print(colored("\n=== Classification Result ===", "cyan"))
        print(f"Severity: {colored(result.severity, 'yellow')}")
        print(f"Confidence: {result.confidence:.2%}")
        
        if result.threats:
            print(colored("\nThreats Detected:", "red"))
            for threat in result.threats:
                print(f"  - {threat}")
        else:
            print(colored("\nNo threats detected", "green"))


def cmd_sanitize(args):
    """Sanitize text."""
    from src.sanitizer import InputSanitizer, OutputSanitizer
    from src.core.config import get_settings
    
    settings = get_settings()
    
    if args.output:
        sanitizer = OutputSanitizer(settings)
    else:
        sanitizer = InputSanitizer(settings)
    
    # Get text
    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    
    sanitized = sanitizer.sanitize(text)
    
    if args.json:
        print(json.dumps({
            "original": text,
            "sanitized": sanitized,
        }, indent=2))
    else:
        print(colored("\n=== Sanitized Output ===", "cyan"))
        print(sanitized)


def cmd_process(args):
    """Process text through the full pipeline."""
    from src.core.pipeline import SecurityPipeline
    from src.core.config import get_settings
    
    async def run():
        settings = get_settings()
        pipeline = SecurityPipeline(settings)
        
        # Get text
        if args.text:
            text = args.text
        elif args.file:
            with open(args.file, 'r') as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        
        result = await pipeline.process(text, user_id=args.user)
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(colored("\n=== Pipeline Result ===", "cyan"))
            print(f"Action: {colored(result.action.value, 'yellow')}")
            print(f"Severity: {result.severity.value}")
            
            if result.threats_detected:
                print(colored("\nThreats:", "red"))
                for threat in result.threats_detected:
                    print(f"  - {threat}")
            
            if result.response:
                print(colored("\nResponse:", "green"))
                print(result.response)
    
    asyncio.run(run())


def cmd_validate(args):
    """Validate text."""
    from src.validation import ValidationEngine
    
    async def run():
        engine = ValidationEngine()
        
        # Get text
        if args.text:
            text = args.text
        elif args.file:
            with open(args.file, 'r') as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        
        result = await engine.validate(text)
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(colored("\n=== Validation Result ===", "cyan"))
            status_color = "green" if result.is_valid else "red"
            print(f"Valid: {colored(str(result.is_valid), status_color)}")
            print(f"Errors: {result.error_count}")
            print(f"Warnings: {result.warning_count}")
            
            if result.violations:
                print(colored("\nViolations:", "yellow"))
                for v in result.violations:
                    severity_color = "red" if v.severity.value in ["error", "critical"] else "yellow"
                    print(f"  [{colored(v.severity.value.upper(), severity_color)}] {v.message}")
    
    asyncio.run(run())


def cmd_test_api(args):
    """Test API endpoint."""
    import requests
    
    base_url = f"http://{args.host}:{args.port}"
    
    # Health check
    print(colored("Testing health endpoint...", "cyan"))
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        if resp.status_code == 200:
            print(colored("  Health check passed", "green"))
            print(f"  {json.dumps(resp.json(), indent=2)}")
        else:
            print(colored(f"  Health check failed: {resp.status_code}", "red"))
    except Exception as e:
        print(colored(f"  Connection failed: {e}", "red"))
        return
    
    # Test classify endpoint
    if args.text:
        print(colored("\nTesting classify endpoint...", "cyan"))
        resp = requests.post(
            f"{base_url}/api/v1/classify",
            json={"text": args.text},
            timeout=30,
        )
        if resp.status_code == 200:
            print(colored("  Classification successful", "green"))
            print(f"  {json.dumps(resp.json(), indent=2)}")
        else:
            print(colored(f"  Classification failed: {resp.status_code}", "red"))


def cmd_config(args):
    """Show configuration."""
    from src.core.config import get_settings
    
    settings = get_settings()
    
    if args.json:
        # Convert to dict for JSON output
        config_dict = {
            "app": {
                "name": settings.app.name,
                "version": settings.app.version,
                "debug": settings.app.debug,
            },
            "server": {
                "host": settings.server.host,
                "port": settings.server.port,
            },
            "security": {
                "block_severity": settings.security.block_severity,
                "sanitize_severity": settings.security.sanitize_severity,
            },
        }
        print(json.dumps(config_dict, indent=2))
    else:
        print(colored("\n=== VeilArmor Configuration ===", "cyan"))
        print(f"\nApp Name: {settings.app.name}")
        print(f"Version: {settings.app.version}")
        print(f"Debug: {settings.app.debug}")
        print(f"\nServer: {settings.server.host}:{settings.server.port}")
        print(f"\nBlock Severity: {settings.security.block_severity}")
        print(f"Sanitize Severity: {settings.security.sanitize_severity}")


def cmd_version(args):
    """Show version information."""
    from src.core.config import get_settings
    
    settings = get_settings()
    
    print(f"VeilArmor v{settings.app.version}")
    print(f"Python {sys.version}")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="VeilArmor - Enterprise LLM Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show banner",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    serve_parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    serve_parser.add_argument("--log-level", default="info", help="Log level")
    serve_parser.set_defaults(func=cmd_serve)
    
    # classify command
    classify_parser = subparsers.add_parser("classify", help="Classify text for threats")
    classify_parser.add_argument("text", nargs="?", help="Text to classify")
    classify_parser.add_argument("-f", "--file", help="Read text from file")
    classify_parser.add_argument("--json", action="store_true", help="Output as JSON")
    classify_parser.set_defaults(func=cmd_classify)
    
    # sanitize command
    sanitize_parser = subparsers.add_parser("sanitize", help="Sanitize text")
    sanitize_parser.add_argument("text", nargs="?", help="Text to sanitize")
    sanitize_parser.add_argument("-f", "--file", help="Read text from file")
    sanitize_parser.add_argument("--output", action="store_true", help="Use output sanitizer")
    sanitize_parser.add_argument("--json", action="store_true", help="Output as JSON")
    sanitize_parser.set_defaults(func=cmd_sanitize)
    
    # process command
    process_parser = subparsers.add_parser("process", help="Process through full pipeline")
    process_parser.add_argument("text", nargs="?", help="Text to process")
    process_parser.add_argument("-f", "--file", help="Read text from file")
    process_parser.add_argument("--user", help="User ID")
    process_parser.add_argument("--json", action="store_true", help="Output as JSON")
    process_parser.set_defaults(func=cmd_process)
    
    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate text")
    validate_parser.add_argument("text", nargs="?", help="Text to validate")
    validate_parser.add_argument("-f", "--file", help="Read text from file")
    validate_parser.add_argument("--json", action="store_true", help="Output as JSON")
    validate_parser.set_defaults(func=cmd_validate)
    
    # test-api command
    test_parser = subparsers.add_parser("test-api", help="Test API endpoints")
    test_parser.add_argument("--host", default="localhost", help="API host")
    test_parser.add_argument("--port", type=int, default=8000, help="API port")
    test_parser.add_argument("--text", help="Text to test with")
    test_parser.set_defaults(func=cmd_test_api)
    
    # config command
    config_parser = subparsers.add_parser("config", help="Show configuration")
    config_parser.add_argument("--json", action="store_true", help="Output as JSON")
    config_parser.set_defaults(func=cmd_config)
    
    # version command
    version_parser = subparsers.add_parser("version", help="Show version")
    version_parser.set_defaults(func=cmd_version)
    
    args = parser.parse_args()
    
    if not args.no_banner and args.command != "version":
        print_banner()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
