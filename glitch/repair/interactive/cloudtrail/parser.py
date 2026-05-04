from dataclasses import dataclass
from typing import List, Optional
import json


@dataclass
class CloudTrailEvent:
    event_name: str
    event_source: str
    request_parameters: dict
    response_elements: Optional[dict]
    event_time: str
    user_agent: Optional[str]


class CloudTrailParser:
    @staticmethod
    def parse_file(path: str) -> List[CloudTrailEvent]:
        with open(path) as f:
            data = json.load(f)
        return CloudTrailParser.parse_json(data)

    @staticmethod
    def parse_json(data: dict) -> List[CloudTrailEvent]:
        records = data.get("Records", [data])
        events: List[CloudTrailEvent] = []
        for record in records:
            events.append(
                CloudTrailEvent(
                    event_name=record.get("eventName", ""),
                    event_source=record.get("eventSource", ""),
                    request_parameters=record.get("requestParameters", {}) or {},
                    response_elements=record.get("responseElements"),
                    event_time=record.get("eventTime", ""),
                    user_agent=record.get("userAgent"),
                )
            )
        return events
