from splunk_client import SplunkClient
from event_parser import parse_event
from mitre_mapper import get_mitre
from risk_engine import calculate_risk
from windows_events import get_windows_event
from ai_engine import AIEngine


# ---------------------------------------
# Connect to Splunk
# ---------------------------------------

splunk = SplunkClient()


# ---------------------------------------
# Get latest Windows Security event
# ---------------------------------------

events = splunk.search(
    "search index=main source=WinEventLog:Security | head 1"
)


if not events:
    print("No events found.")
    exit()


# ---------------------------------------
# Raw event
# ---------------------------------------

raw_event = events[0]["_raw"]


# ---------------------------------------
# Parse Windows Event
# ---------------------------------------

parsed_event = parse_event(raw_event)


# ---------------------------------------
# Windows Event Knowledge Base
# ---------------------------------------

parsed_event["windows_event"] = get_windows_event(
    parsed_event["event_id"]
)


# ---------------------------------------
# MITRE ATT&CK Mapping
# ---------------------------------------

parsed_event["mitre"] = get_mitre(
    parsed_event["event_id"]
)


# ---------------------------------------
# Risk Calculation
# ---------------------------------------

parsed_event["risk"] = calculate_risk(
    parsed_event
)


# ---------------------------------------
# Display Parsed Event
# ---------------------------------------

print("=" * 60)
print("PARSED EVENT")
print("=" * 60)

print(parsed_event)


# ---------------------------------------
# Display Raw Event
# ---------------------------------------

print("\n" + "=" * 60)
print("RAW WINDOWS EVENT")
print("=" * 60)

print(raw_event)


# ---------------------------------------
# AI SOC Analysis
# ---------------------------------------

print("\n" + "=" * 60)
print("AI SOC ANALYSIS")
print("=" * 60)


ai = AIEngine()


analysis = ai.analyze(
    parsed_event,
    raw_event
)


print(analysis)