import io

import lantern.logger as logger_module
from lantern.logger import _SpinnerSink


class _RecordingSpinner:
    def __init__(self):
        self.written = []

    def write(self, text):
        self.written.append(text)


def test_sink_writes_directly_without_spinner():
    stream = io.StringIO()
    sink = _SpinnerSink(stream)

    sink.write("INFO     | hello\n")

    assert stream.getvalue() == "INFO     | hello\n"


def test_sink_routes_records_through_attached_spinner():
    stream = io.StringIO()
    sink = _SpinnerSink(stream)
    spinner = _RecordingSpinner()
    sink.attach(spinner)

    sink.write("INFO     | hello\n")

    # Yaspin.write owns the line break, so the sink must not add a second one.
    assert spinner.written == ["INFO     | hello"]
    assert stream.getvalue() == ""


def test_sink_preserves_embedded_newlines():
    stream = io.StringIO()
    sink = _SpinnerSink(stream)
    spinner = _RecordingSpinner()
    sink.attach(spinner)

    sink.write("first\nsecond\n")

    assert spinner.written == ["first\nsecond"]


def test_sink_only_strips_one_trailing_newline():
    stream = io.StringIO()
    sink = _SpinnerSink(stream)
    spinner = _RecordingSpinner()
    sink.attach(spinner)

    sink.write("hello\n\n")

    assert spinner.written == ["hello\n"]


def test_detach_ignores_a_different_spinner():
    sink = _SpinnerSink(io.StringIO())
    first = _RecordingSpinner()
    second = _RecordingSpinner()
    sink.attach(first)

    sink.detach(second)

    assert sink._spinner is first

    sink.detach(first)

    assert sink._spinner is None


def test_module_attach_and_detach_use_the_registered_sink():
    spinner = _RecordingSpinner()

    try:
        logger_module.attach_spinner(spinner)
        assert logger_module._sink._spinner is spinner
    finally:
        logger_module.detach_spinner(spinner)

    assert logger_module._sink._spinner is None
