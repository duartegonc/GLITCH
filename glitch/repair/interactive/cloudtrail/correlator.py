from typing import Dict, List, Optional


class CloudTrailCorrelator:
    def __init__(self, mapping: Optional[Dict[str, str]] = None) -> None:
        self.mapping = mapping or {}

    def correlate(self, physical_id: str, _logical_ids: List[str]) -> str:
        if physical_id in self.mapping:
            return self.mapping[physical_id]
        return physical_id
