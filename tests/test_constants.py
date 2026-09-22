import importlib

import lantern.constants as constants


def test_env_int_reads_override(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_INT", "7")

    assert constants._env_int("LANTERN_TEST_INT", 4) == 7


def test_env_int_falls_back_when_unset(monkeypatch):
    monkeypatch.delenv("LANTERN_TEST_INT", raising=False)

    assert constants._env_int("LANTERN_TEST_INT", 4) == 4


def test_env_int_falls_back_when_malformed(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_INT", "not-a-number")

    assert constants._env_int("LANTERN_TEST_INT", 4) == 4


def test_env_int_enforces_minimum(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_INT", "0")

    assert constants._env_int("LANTERN_TEST_INT", 4, minimum=1) == 4


def test_env_float_reads_override(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_FLOAT", "2.5")

    assert constants._env_float("LANTERN_TEST_FLOAT", 1.0) == 2.5


def test_env_float_falls_back_when_malformed(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_FLOAT", "fast")

    assert constants._env_float("LANTERN_TEST_FLOAT", 1.0) == 1.0


def test_env_float_enforces_minimum(monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_FLOAT", "0")

    assert constants._env_float("LANTERN_TEST_FLOAT", 0.25, minimum=0.01) == 0.25


def test_knobs_are_wired_to_environment(monkeypatch):
    monkeypatch.setenv("LANTERN_NAME_MAX_WORKERS", "8")
    monkeypatch.setenv("LANTERN_PASSIVE_QUIET_PERIOD", "1.5")

    reloaded = importlib.reload(constants)
    try:
        assert reloaded.NAME.MAX_WORKERS == 8
        assert reloaded.PASSIVE.QUIET_PERIOD == 1.5
    finally:
        monkeypatch.delenv("LANTERN_NAME_MAX_WORKERS", raising=False)
        monkeypatch.delenv("LANTERN_PASSIVE_QUIET_PERIOD", raising=False)
        importlib.reload(constants)
