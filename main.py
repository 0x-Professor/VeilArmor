#!/usr/bin/env python3
"""
VeilArmor v2.0 - Main Entry Point

Enterprise-grade LLM security framework providing multi-layered
protection against prompt injections, jailbreaks, PII leakage,
and sophisticated security threats.

Usage:
    python main.py                    # Run with default settings
    python main.py --host 0.0.0.0     # Custom host
    python main.py --port 8080        # Custom port
    python main.py --workers 4        # Multiple workers
    python main.py --dev              # Development mode
"""

import argparse
import os
import sys
from typing import Optional

import uvicorn

from src.core.config import get_settings, Settings
from src.utils.logger import setup_logging, get_logger


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VeilArmor v2.0 - LLM Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py                        # Start with defaults
    python main.py --port 8080            # Custom port
    python main.py --host 0.0.0.0 -w 4    # Production mode
    python main.py --dev                  # Development mode
        """,
    )
    
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind (default: from config or 0.0.0.0)",
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Port to listen on (default: from config or 8000)",
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Number of worker processes (default: 1)",
    )
    
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Run in development mode with auto-reload",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to configuration file",
    )
    
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show version and exit",
    )
    
    return parser.parse_args()


def get_version() -> str:
    """Get application version."""
    return "2.0.0"


def print_banner(settings: Settings, host: str, port: int):
    """Print startup banner."""
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗   ██╗███████╗██╗██╗      █████╗ ██████╗ ███╗   ███╗██████╗ ║
║   ██║   ██║██╔════╝██║██║     ██╔══██╗██╔══██╗████╗ ████║██╔══██╗║
║   ██║   ██║█████╗  ██║██║     ███████║██████╔╝██╔████╔██║██████╔╝║
║   ╚██╗ ██╔╝██╔══╝  ██║██║     ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██╗║
║    ╚████╔╝ ███████╗██║███████╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║║
║     ╚═══╝  ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝║
║                                                                  ║
║                 Enterprise LLM Security Framework                ║
║                          Version {get_version()}                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

    [*] Starting VeilArmor Security Server
    [*] Host: {host}
    [*] Port: {port}
    [*] Environment: {settings.app.environment}
    [*] Debug: {settings.app.debug}
    [*] API Docs: http://{host}:{port}/docs

"""
    print(banner)


def run_server(
    settings: Settings,
    host: Optional[str] = None,
    port: Optional[int] = None,
    workers: Optional[int] = None,
    dev_mode: bool = False,
    debug: bool = False,
):
    """Run the VeilArmor server."""
    
    # Determine settings
    final_host = host or getattr(settings.server, 'host', '0.0.0.0')
    final_port = port or getattr(settings.server, 'port', 8000)
    final_workers = workers or 1
    reload = dev_mode or settings.app.debug
    log_level = "debug" if debug else settings.logging.level.lower()
    
    # Print banner
    print_banner(settings, final_host, final_port)
    
    # Get logger
    logger = get_logger("veilarmor.main")
    logger.info(
        f"Starting VeilArmor server on {final_host}:{final_port} "
        f"with {final_workers} worker(s), reload={reload}"
    )
    
    # Uvicorn configuration
    uvicorn_config = {
        "app": "src.api.server:app",
        "host": final_host,
        "port": final_port,
        "log_level": log_level,
        "access_log": True,
    }
    
    if reload:
        # Development mode - single process with reload
        uvicorn_config["reload"] = True
        uvicorn_config["reload_dirs"] = ["src"]
    elif final_workers > 1:
        # Production mode with multiple workers
        uvicorn_config["workers"] = final_workers
    
    # Run server
    try:
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()
    
    # Show version and exit
    if args.version:
        print(f"VeilArmor v{get_version()}")
        sys.exit(0)
    
    # Set config path if provided
    if args.config:
        os.environ["VEILARMOR_CONFIG"] = args.config
    
    # Set debug mode
    if args.debug:
        os.environ["VEILARMOR_DEBUG"] = "true"
    
    # Load settings
    try:
        settings = get_settings()
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        sys.exit(1)
    
    # Setup logging
    log_level = "DEBUG" if args.debug else settings.logging.level
    setup_logging(level=log_level)
    
    # Run server
    run_server(
        settings=settings,
        host=args.host,
        port=args.port,
        workers=args.workers,
        dev_mode=args.dev,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()
