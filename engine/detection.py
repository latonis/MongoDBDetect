import pymongo
import os
import yaml

import rule


class DetectionEngine:
    def __init__(self):
        self.rules: list(rule.DetectionRule) = []
        self.connect_to_client()
        self.get_change_stream()

    def add_rule(self, rule: rule.DetectionRule):
        if not rule:
            return

        self.rules.append(rule)

    def add_rules(self, directory: str = ""):
        if not directory:
            return

        for root, _, files in os.walk(directory):
            for entry in files:
                with open(os.path.join(root, entry), "rb") as yaml_file:
                    rule_def = yaml.safe_load(yaml_file)
                    self.add_rule(rule.DetectionRule(**rule_def))

    def connect_to_client(self, URI: str = ""):
        if not URI:
            env_uri = os.getenv("CHANGE_STREAM_DB", "")
            if not (env_uri):
                return None
            URI = env_uri
        self.mc = pymongo.MongoClient(URI)

    def get_change_stream(self):
        pipeline = [{"$match": {"operationType": {"$in": ["insert"]}}}]

        self.cursor = (
            self.mc.get_database(os.getenv("CHANGE_DB_NAME", ""))
            .get_collection(os.getenv("CHANGE_COLLECTION_NAME", ""))
            .watch(pipeline=pipeline)
        )

    def get_rules(self):
        return self.rules

    def process_log(self, log: dict):
        if not log:
            return
        hits = []
        for rule_entry in self.get_rules():
            fields = rule_entry.top_level_fields()
            for field in fields:
                if field in log:
                    for detection in rule_entry.detection_logic.get(field):
                        if detection in log.get(field):
                            hits.append(("alert!!", log, rule_entry.detection_logic))
        print(hits)


engine = DetectionEngine()

# add all the rules
engine.add_rules("./rules/")

# watch the change stream
for document in engine.cursor:
    log = document.get("fullDocument")
    engine.process_log(log)
