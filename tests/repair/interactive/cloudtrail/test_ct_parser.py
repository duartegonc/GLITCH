import unittest
from glitch.repair.interactive.cloudtrail.parser import CloudTrailParser, CloudTrailEvent


class TestCloudTrailParser(unittest.TestCase):
    def test_parse_records_array(self) -> None:
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/s3_create_private.json"
        )
        assert len(events) == 1
        assert events[0].event_name == "CreateBucket"
        assert events[0].event_source == "s3.amazonaws.com"
        assert events[0].request_parameters["bucketName"] == "my-test-bucket"
        assert events[0].request_parameters["x-amz-acl"] == "private"
        assert events[0].event_time == "2024-01-01T00:00:00Z"
        assert events[0].user_agent == "aws-cli/2.0.0"

    def test_parse_single_event(self) -> None:
        data = {
            "eventName": "CreateBucket",
            "eventSource": "s3.amazonaws.com",
            "requestParameters": {"bucketName": "single-bucket"},
            "responseElements": None,
            "eventTime": "2024-01-01T00:00:00Z",
            "userAgent": "aws-cli/2.0.0",
        }
        events = CloudTrailParser.parse_json(data)
        assert len(events) == 1
        assert events[0].event_name == "CreateBucket"
        assert events[0].request_parameters["bucketName"] == "single-bucket"

    def test_parse_missing_fields(self) -> None:
        data = {
            "Records": [
                {
                    "eventName": "CreateBucket",
                    "eventSource": "s3.amazonaws.com",
                }
            ]
        }
        events = CloudTrailParser.parse_json(data)
        assert len(events) == 1
        assert events[0].request_parameters == {}
        assert events[0].response_elements is None
        assert events[0].user_agent is None
