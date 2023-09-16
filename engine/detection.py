import pymongo
import os
import yaml
import json
import rule


class DetectionEngine:
    def __init__(self):
        self.resume_token = None
        self.rules: list(rule.DetectionRule) = []
        self.connect_to_client()
        self.get_resume_token()
        self.get_change_stream()

    def add_rule(self, rule: rule.DetectionRule) -> None:
        if not rule:
            return

        self.rules.append(rule)

    def add_rules(self, directory: str = "") -> None:
        if not directory:
            return

        for root, _, files in os.walk(directory):
            for entry in files:
                if entry.endswith(".yml") or entry.endswith(".yaml"):
                    with open(os.path.join(root, entry), "rb") as yaml_file:
                        rule_def = yaml.safe_load(yaml_file)
                        self.add_rule(rule.DetectionRule(**rule_def))

    def alert(self, msg):
        print("\033[91m {}\033[00m".format("alert!!"), msg)

    def connect_to_client(self, URI: str = "") -> None:
        if not URI:
            env_uri = os.getenv("CHANGE_STREAM_DB", "")
            if not (env_uri):
                return None
            URI = env_uri
        self.mongo_client = pymongo.MongoClient(URI)

    def get_change_stream(self) -> None:
        pipeline = [{"$match": {"operationType": {"$in": ["insert"]}}}]

        if self.resume_token:
            self.cursor = (
                self.mongo_client.get_database(os.getenv("CHANGE_DB_NAME", ""))
                .get_collection(os.getenv("CHANGE_COLLECTION_NAME", ""))
                .watch(pipeline=pipeline, resume_after=self.resume_token)
            )
        else:
            self.cursor = (
                self.mongo_client.get_database(os.getenv("CHANGE_DB_NAME", ""))
                .get_collection(os.getenv("CHANGE_COLLECTION_NAME", ""))
                .watch(pipeline=pipeline)
            )

    def get_resume_token(self) -> None:
        self.config_collection = self.mongo_client.get_database(
            os.getenv("CHANGE_DB_NAME", "")
        ).get_collection(os.getenv("CONFIG_COLLECTION_NAME", ""))
        token = self.config_collection.find_one({"resume_token": {"$exists": True}})
        if token:
            self.resume_token = token.get("resume_token")

    def get_rules(self) -> list:
        return self.rules

    def process_log(self, log: dict) -> list:
        if not log:
            return
        hits = []
        for rule_entry in self.get_rules():
            fields = rule_entry.top_level_fields()
            for field in fields:
                if field in log:
                    for detection in rule_entry.detection_logic.get(field):
                        if detection in log.get(field):
                            self.alert(
                                f"{rule_entry.uuid} - {rule_entry.name}\n{json.dumps(log, indent=2, default=str)}"
                            )
                            hits.append(rule_entry.uuid)
        return hits

    def save_token(self) -> None:
        self.config_collection.update_one(
            {"resume_token": {"$exists": True}},
            {"$set": {"resume_token": self.resume_token}},
            upsert=True,
        )


if __name__ == "__main__":
    try:
        engine = DetectionEngine()

        # add all the rules
        engine.add_rules("./rules/")

        # watch the change stream
        for document in engine.cursor:
            log = document.get("fullDocument")
            engine.process_log(log)
            engine.resume_token = engine.cursor.resume_token
    except KeyboardInterrupt:
        print("Exiting the detection engine...")
    except Exception as e:
        print(f"Something went wrong: {e}")
    finally:
        engine.save_token()
