import unittest
from glitch.repair.interactive.cloudtrail.parser import CloudTrailParser
from glitch.repair.interactive.cloudtrail.transform import CloudTrailTransform
from glitch.repair.interactive.values import UNDEF


class TestCloudTrailTransform(unittest.TestCase):
    def test_s3_create_bucket(self) -> None:
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_create_private.json"
        )
        state = CloudTrailTransform.build_system_state(events)
        assert "aws_s3_bucket:my-test-bucket" in state.state
        assert state.state["aws_s3_bucket:my-test-bucket"].attrs["state"] == "present"
        assert state.state["aws_s3_bucket:my-test-bucket"].attrs["acl"] == "private"

    def test_s3_delete_bucket(self) -> None:
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_delete_bucket.json"
        )
        state = CloudTrailTransform.build_system_state(events)
        assert "aws_s3_bucket:my-test-bucket" in state.state
        assert state.state["aws_s3_bucket:my-test-bucket"].attrs["state"] == "absent"
        assert state.state["aws_s3_bucket:my-test-bucket"].attrs["acl"] == UNDEF

    def test_s3_put_acl(self) -> None:
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_put_acl_public.json"
        )
        state = CloudTrailTransform.build_system_state(events)
        assert "aws_s3_bucket:my-drifted-bucket" in state.state
        assert state.state["aws_s3_bucket:my-drifted-bucket"].attrs["acl"] == "public-read"

    def test_multiple_events(self) -> None:
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_create_public.json"
        )
        events += CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_put_acl_public.json"
        )
        state = CloudTrailTransform.build_system_state(events)
        assert "aws_s3_bucket:my-drifted-bucket" in state.state
        assert state.state["aws_s3_bucket:my-drifted-bucket"].attrs["state"] == "present"
        assert state.state["aws_s3_bucket:my-drifted-bucket"].attrs["acl"] == "public-read"
