"""Tests for ActShield CLI threat modeling commands."""

import json
import tempfile
import pathlib
import pytest
from typer.testing import CliRunner

from actshield.cli.main import app

runner = CliRunner()


def test_cli_threat_model():
    result = runner.invoke(app, ["threat", "model"])
    assert result.exit_code == 0
    assert "Threat Model" in result.output or "Assets" in result.output or "Threats" in result.output


def test_cli_threat_model_json():
    result = runner.invoke(app, ["threat", "model", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "system_name" in data or "asset_count" in data or "threat_count" in data


def test_cli_threat_list():
    result = runner.invoke(app, ["threat", "list"])
    assert result.exit_code == 0
    assert "THREAT" in result.output.upper() or "SEVERITY" in result.output.upper()


def test_cli_threat_list_json():
    result = runner.invoke(app, ["threat", "list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) >= 5


def test_cli_threat_list_filter_severity():
    result = runner.invoke(app, ["threat", "list", "--severity", "CRITICAL", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    for item in data:
        assert item["severity"] == "CRITICAL"


def test_cli_threat_inspect():
    result = runner.invoke(app, ["threat", "inspect", "thr_indirect_prompt_injection"])
    assert result.exit_code == 0
    assert "thr_indirect_prompt_injection" in result.output or "Indirect Prompt Injection" in result.output


def test_cli_threat_analyze():
    result = runner.invoke(app, ["threat", "analyze"])
    assert result.exit_code == 0
    assert "Analysis" in result.output or "Risk Score" in result.output or "Score" in result.output


def test_cli_threat_graph():
    result = runner.invoke(app, ["threat", "graph"])
    assert result.exit_code == 0


def test_cli_threat_report():
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = pathlib.Path(tmp_dir) / "threat-report.md"
        result = runner.invoke(app, ["threat", "report", "--output", str(out_path)])
        assert result.exit_code == 0
        assert out_path.exists()
        content = out_path.read_text(encoding="utf-8")
        assert len(content) > 100
        assert "# " in content


def test_cli_threat_export_json():
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = pathlib.Path(tmp_dir) / "threat-model.json"
        result = runner.invoke(app, ["threat", "export", "--format", "json", "--output", str(out_path)])
        assert result.exit_code == 0
        assert out_path.exists()
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert "threats_by_severity" in data or "model" in data or "system_name" in data
