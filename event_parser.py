import re
from mitre_mapper import get_mitre


def find(pattern, text):
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else "Unknown"


def parse_event(raw):

    event = {}

    event["event_id"] = find(r"EventCode=(\d+)", raw)
    event["computer"] = find(r"ComputerName=(.*)", raw)

    event_id = event["event_id"]

    # -----------------------------
    # Event ID 4798
    # -----------------------------
    if event_id == "4798":

        users = re.findall(r"Account Name:\s+(.*)", raw)

        if len(users) >= 2:
            event["account"] = users[1].strip()
        elif len(users) == 1:
            event["account"] = users[0].strip()
        else:
            event["account"] = "Unknown"

        event["process"] = find(r"Process Name:\s+(.*)", raw)

    # -----------------------------
    # Event ID 4672
    # -----------------------------
    elif event_id == "4672":

        event["account"] = find(r"Account Name:\s+(.*)", raw)

        event["process"] = "N/A"

        privileges = re.search(
            r"Privileges:\s+(.*?)$",
            raw,
            re.DOTALL
        )

        if privileges:
            event["privileges"] = privileges.group(1).strip()
        else:
            event["privileges"] = "Unknown"

    # -----------------------------
    # Event ID 4624
    # -----------------------------
    elif event_id == "4624":

        users = re.findall(r"Account Name:\s+(.*)", raw)

        if len(users) >= 2:
            event["account"] = users[1].strip()
        elif len(users) == 1:
            event["account"] = users[0].strip()
        else:
            event["account"] = "Unknown"

        event["logon_type"] = find(
            r"Logon Type:\s+(\d+)",
            raw
        )

        event["process"] = find(
            r"Process Name:\s+(.*)",
            raw
        )

    # -----------------------------
    # Event ID 4688
    # -----------------------------
    elif event_id == "4688":

        event["account"] = find(
            r"Account Name:\s+(.*)",
            raw
        )

        event["process"] = find(
            r"New Process Name:\s+(.*)",
            raw
        )

        event["commandline"] = find(
            r"Process Command Line:\s+(.*)",
            raw
        )

    # -----------------------------
    # Event ID 5379
    # -----------------------------
    elif event_id == "5379":

        event["account"] = find(
            r"Account Name:\s+(.*)",
            raw
        )

        event["process"] = "Credential Manager"

        event["operation"] = find(
            r"Read Operation:\s+(.*)",
            raw
        )

    # -----------------------------
    # Generic Events
    # -----------------------------
    else:

        event["account"] = find(
            r"Account Name:\s+(.*)",
            raw
        )

        event["process"] = find(
            r"Process Name:\s+(.*)",
            raw
        )

    # -----------------------------
    # MITRE ATT&CK Mapping
    # -----------------------------
    event["mitre"] = get_mitre(event["event_id"])

    return event