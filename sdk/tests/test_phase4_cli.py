"""Phase 4 Tests — Attack CLI subcommands."""

import argparse
import unittest
from unittest.mock import patch

from agentguard.__main__ import cli_attack_list, cli_attack_run, cli_attack_replay, cli_attack_report


class TestPhase4CLI(unittest.TestCase):
    """Test CLI subcommand handlers."""

    def test_cli_attack_list(self):
        exit_code = cli_attack_list()
        assert exit_code == 0

    def test_cli_attack_run_all(self):
        args = argparse.Namespace(type=None, limit=5, all=True)
        exit_code = cli_attack_run(args)
        assert exit_code == 0

    def test_cli_attack_run_by_type(self):
        args = argparse.Namespace(type="indirect_prompt_injection", limit=3, all=False)
        exit_code = cli_attack_run(args)
        assert exit_code == 0

    def test_cli_attack_replay(self):
        exit_code = cli_attack_replay("atk_pinj_001")
        assert exit_code == 0


if __name__ == "__main__":
    unittest.main()
