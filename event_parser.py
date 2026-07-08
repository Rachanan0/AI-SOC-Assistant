import re


def extract(text, pattern):
    match = re.search(pattern, text, re.MULTILINE)

    if match:
        return match.group(1).strip()

    return "Unknown"


def parse_event(raw_event):

    event = {}

    event["event_id"] = extract(
        raw_event,
        r"EventCode=(\d+)"
    )

    event["computer"] = extract(
        raw_event,
        r"ComputerName=(.*)"
    )

    # Get Account Name from the User section only
    user_match = re.search(
        r"User:.*?Account Name:\s+([^\r\n]+)",
        raw_event,
        re.DOTALL
    )

    if user_match:
        event["account"] = user_match.group(1).strip()
    else:
        event["account"] = "Unknown"

    event["process"] = extract(
        raw_event,
        r"Process Name:\s+(.*)"
    )

    return event