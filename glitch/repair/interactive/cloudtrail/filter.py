from typing import List
from glitch.repair.interactive.cloudtrail.parser import CloudTrailEvent


class CloudTrailFilter:
    RELEVANT_EVENTS = {
        "s3.amazonaws.com": ["CreateBucket", "PutBucketAcl", "DeleteBucket"],
        "ec2.amazonaws.com": ["RunInstances", "ModifyInstanceAttribute", "TerminateInstances"],
        "iam.amazonaws.com": ["CreateRole", "PutRolePolicy", "DeleteRole"],
    }

    @staticmethod
    def filter(events: List[CloudTrailEvent]) -> List[CloudTrailEvent]:
        result: List[CloudTrailEvent] = []
        for event in events:
            allowed = CloudTrailFilter.RELEVANT_EVENTS.get(event.event_source, [])
            if event.event_name in allowed:
                result.append(event)
        return result
