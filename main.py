"""Main entry point for VeilArmor"""

import uvicorn
from src.core.config import get_settings
from src.utils.logger import setup_logging


def main():
    """Run the VeilArmor server"""
    settings = get_settings()
    setup_logging(level=settings.logging.level)
    
    uvicorn.run(
        "src.api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.app.debug,
        log_level=settings.logging.level.lower()
    )


if __name__ == "__main__":
    main()