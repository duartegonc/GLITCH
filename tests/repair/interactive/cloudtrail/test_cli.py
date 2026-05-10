import unittest
from click.testing import CliRunner
from glitch.__main__ import cli


class TestInfrafixCLI(unittest.TestCase):
    def test_missing_pid_and_cloudtrail_log(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "infrafix",
                "--tech",
                "cloudformation",
                "tests/repair/interactive/cloudtrail/fixtures/drift_template.yaml",
            ],
        )
        assert result.exit_code != 0
        assert "Either PID or --cloudtrail-log must be provided" in result.output

    def test_cloudtrail_log_only(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "infrafix",
                "--tech",
                "cloudformation",
                "--cloudtrail-log",
                "tests/repair/interactive/cloudtrail/fixtures/s3_create_public.json",
                "tests/repair/interactive/cloudtrail/fixtures/drift_template.yaml",
            ],
            input="0\n",
        )
        assert result.exit_code == 0
        assert "Patch applied" in result.output
        assert "Patch 0" in result.output
