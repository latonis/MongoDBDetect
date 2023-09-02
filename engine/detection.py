from engine import rule

class DetectionEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule: rule.DetectionRule):
        self.rules.append(rule)