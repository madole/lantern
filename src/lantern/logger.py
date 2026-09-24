import os
import sys

from loguru import logger

from lantern.constants import LOGGING


class _SpinnerSink:
    """A stderr sink that prints log lines above an active yaspin spinner.

    yaspin redraws its frame in place with a carriage return and no trailing
    newline. A record written straight to the stream therefore shares the
    spinner's line, and the next frame redraws over it, leaving the duplicated,
    interleaved lines that appear when threads log during the listening window.

    ``Yaspin.write`` avoids that: it clears the frame, prints the record on its
    own line, and lets the next frame redraw below it. The owner of the spinner
    registers it for the duration of its animation, so records logged from any
    thread are routed through it while it spins.
    """

    def __init__(self, stream):
        self._stream = stream
        self._spinner = None

    def attach(self, spinner):
        """Draw subsequent records above ``spinner`` until detached."""
        self._spinner = spinner

    def detach(self, spinner=None):
        """Stop routing records through ``spinner``.

        Passing the attached spinner detaches only if it is still the current
        one, so a late detach cannot unbind a newer spinner.
        """
        if spinner is None or spinner is self._spinner:
            self._spinner = None

    def write(self, message):
        spinner = self._spinner
        if spinner is None:
            self._stream.write(message)
            return
        # Yaspin.write appends its own newline; drop the sink's so records do
        # not end up separated by a blank line.
        if message.endswith("\n"):
            message = message[:-1]
        spinner.write(message)


_sink = _SpinnerSink(sys.stderr)


def attach_spinner(spinner):
    """Route log records through ``spinner`` while it animates."""
    _sink.attach(spinner)


def detach_spinner(spinner=None):
    """Stop routing log records through ``spinner``."""
    _sink.detach(spinner)


logger.remove()
logger.level(LOGGING.LEVEL_DEBUG, color=LOGGING.COLOR_DEBUG)
logger.level(LOGGING.LEVEL_INFO, color=LOGGING.COLOR_INFO)
logger.configure(extra=LOGGING.DEFAULT_EXTRA)
logger.add(
    _sink.write,
    level=os.getenv(LOGGING.ENV_LEVEL, LOGGING.DEFAULT_LEVEL),
    format=LOGGING.FORMAT,
    colorize=True,
)
