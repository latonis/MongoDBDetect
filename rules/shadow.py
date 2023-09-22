def rule(event: dict) -> bool:
    if "/etc/shadow" in event.get("command_line"):
        return True
    return False


"""
detection_logic:
  command_line: 
    - /etc/shadow
"""
