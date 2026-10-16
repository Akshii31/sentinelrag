from app import config
from app.security import api_key_is_configured


def test_settings_loads_api_key_from_the_project_root_env_file(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("SENTINELRAG_API_KEY=file-only-test-key\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("SENTINELRAG_API_KEY", raising=False)

    settings = config.Settings.from_env()

    assert api_key_is_configured(settings.api_key)
    assert settings.api_key == "file-only-test-key"


def test_usable_process_key_overrides_env_file_but_placeholder_does_not(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("SENTINELRAG_API_KEY=file-test-key\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)

    monkeypatch.setenv("SENTINELRAG_API_KEY", "process-test-key")
    assert config.Settings.from_env().api_key == "process-test-key"

    monkeypatch.setenv("SENTINELRAG_API_KEY", "replace-with-a-long-random-local-key")
    settings = config.Settings.from_env()
    assert settings.api_key == "file-test-key"
    assert api_key_is_configured(settings.api_key)
