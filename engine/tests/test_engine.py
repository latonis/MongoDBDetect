import detection


def test_shadow():
    test_log = {
        "hostname": "pop-os",
        "ip_address": "127.0.1.1",
        "parent_pid": 1,
        "pid": 2,
        "path": "/usr/bin/sudo",
        "binary": "sudo",
        "arguments": "cat /etc/shadow",
        "command_line": "/usr/bin/sudo cat /etc/shadow",
    }

    engine = detection.DetectionEngine()
    engine.add_rules("./rules/")

    expected = ["5e3566a3-9f19-4ac7-8710-ec5fb09260ed"]

    results = engine.process_log(test_log)

    assert results == expected


def test_pipe():
    test_log = {
        "hostname": "pop-os",
        "ip_address": "127.0.1.1",
        "parent_pid": 1,
        "pid": 2,
        "path": "/usr/bin/sudo",
        "binary": "sudo",
        "arguments": "cat /etc/passwd > /tmp/badfile",
        "command_line": "/usr/bin/sudo cat /etc/passwd > /tmp/badfile",
    }

    engine = detection.DetectionEngine()
    engine.add_rules("./rules/")

    expected = ["f825ad39-d4b1-41da-91ec-6438d8dc9ace"]

    results = engine.process_log(test_log)

    assert results == expected
