from dataclasses import dataclass

@dataclass
class DetectionRule:
    name: str
    uuid: str
    detection_logic: dict

    def top_level_fields(self) -> list[str]:
        return list(self.detection_logic.keys())

