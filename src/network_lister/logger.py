import os
import sys

from loguru import logger

from network_lister.constants import LOGGING

logger.remove()
logger.level(LOGGING.LEVEL_DEBUG, color=LOGGING.COLOR_DEBUG)
logger.level(LOGGING.LEVEL_INFO, color=LOGGING.COLOR_INFO)
logger.configure(extra=LOGGING.DEFAULT_EXTRA)
logger.add(
    sys.stderr,
    level=os.getenv(LOGGING.ENV_LEVEL, LOGGING.DEFAULT_LEVEL),
    format=LOGGING.FORMAT,
    colorize=True,
)
