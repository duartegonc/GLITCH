import unittest
from glitch.repair.interactive.cloudtrail.parser import CloudTrailEvent
from glitch.repair.interactive.cloudtrail.filter import CloudTrailFilter


class TestCloudTrailFilter(unittest.TestCase):
    def test_filter_relevant_s3(self) -> None:
        events = [
            CloudTrailEvent(
                "CreateBucket", "s3.amazonaws.com", {}, None, "", None
            ),
            CloudTrailEvent(
                "PutBucketAcl", "s3.amazonaws.com", {}, None, "", None
            ),
        ]
        result = CloudTrailFilter.filter(events)
        assert len(result) == 2

    def test_filter_reject_irrelevant(self) -> None:
        events = [
            CloudTrailEvent(
                "ListBuckets", "s3.amazonaws.com", {}, None, "", None
            ),
            CloudTrailEvent(
                "DescribeInstances", "ec2.amazonaws.com", {}, None, "", None
            ),
        ]
        result = CloudTrailFilter.filter(events)
        assert len(result) == 0

    def test_filter_mixed(self) -> None:
        events = [
            CloudTrailEvent(
                "CreateBucket", "s3.amazonaws.com", {}, None, "", None
            ),
            CloudTrailEvent(
                "ListBuckets", "s3.amazonaws.com", {}, None, "", None
            ),
            CloudTrailEvent(
                "DeleteBucket", "s3.amazonaws.com", {}, None, "", None
            ),
        ]
        result = CloudTrailFilter.filter(events)
        assert len(result) == 2
        assert result[0].event_name == "CreateBucket"
        assert result[1].event_name == "DeleteBucket"
