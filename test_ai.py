from splunk_client import SplunkClient
from event_parser import parse_event
from mitre_mapper import get_mitre
from risk_engine import calculate_risk
from correlation_engine import correlation_engine
from ai_engine import AIEngine
from alert_manager import AlertManager
from report_generator import generate_report


# ---------------------------------------
# Connect to Splunk
# ---------------------------------------

splunk = SplunkClient()


# ---------------------------------------
# Get latest Windows Security events
# ---------------------------------------

events = splunk.search(
    "search index=main source=WinEventLog:Security | head 20"
)


if not events:
    print("No events found")
    exit()


# ---------------------------------------
# Parse multiple events
# ---------------------------------------

parsed_events = []


for event in events:

    raw = event["_raw"]

    parsed = parse_event(raw)


    # MITRE Mapping
    parsed["mitre"] = get_mitre(
        parsed["event_id"]
    )


    # Risk Calculation
    parsed["risk"] = calculate_risk(
        parsed
    )


    parsed_events.append(parsed)



# ---------------------------------------
# Correlation Detection
# ---------------------------------------

correlation_alerts = correlation_engine(
    parsed_events
)


correlation_context = None


if correlation_alerts:

    correlation_context = correlation_alerts[0]



# Use latest event for AI analysis

parsed_event = parsed_events[0]

raw_event = events[0]["_raw"]



# ---------------------------------------
# Display Event
# ---------------------------------------

print("="*60)
print("PARSED EVENT")
print("="*60)

print(parsed_event)



# ---------------------------------------
# AI SOC Analysis
# ---------------------------------------

print("\n" + "="*60)
print("AI SOC ANALYSIS")
print("="*60)


ai = AIEngine()


analysis = ai.analyze(
    parsed_event,
    raw_event,
    correlation_context
)


print(analysis)



# ---------------------------------------
# Create SOC Alert
# ---------------------------------------

manager = AlertManager()


alert = manager.create_alert(
    parsed_event,
    correlation_context
)


print("\n" + "="*60)
print("SOC ALERT")
print("="*60)


print(alert)



# ---------------------------------------
# Generate Incident Report
# ---------------------------------------

report = generate_report(
    alert
)


print("\nIncident Report Created:")
print(report)