from collections import Counter


def detect_bruteforce(events):

    failed_logins = []

    for event in events:

        if event.get("event_id") == "4625":
            failed_logins.append(event)


    if len(failed_logins) >= 5:

        return {
            "alert": "Possible Brute Force Attack",
            "severity": "High",
            "events": [
                "4625 Failed Logon",
                f"Failed Attempts: {len(failed_logins)}"
            ]
        }


    return None



def correlation_engine(events):

    alerts = []


    brute_force = detect_bruteforce(events)

    if brute_force:
        alerts.append(brute_force)


    return alerts