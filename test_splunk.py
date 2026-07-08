from splunk_client import SplunkClient
from event_parser import parse_event


splunk = SplunkClient()


query = """
search index=main sourcetype="WinEventLog:Security"
| head 5
"""


events = splunk.search(query)


for event in events:

    print("\n====================")

    parsed = parse_event(
        event["_raw"]
    )

    print("Event ID :", parsed["event_id"])
    print("Computer :", parsed["computer"])
    print("User     :", parsed["account"])
    print("Process  :", parsed["process"])