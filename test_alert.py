from alert_manager import AlertManager
from report_generator import generate_report


sample_event = {

    "event_id":"4625",

    "computer":"Rachana",

    "account":"admin",

    "process":"Unknown",

    "risk":
    {
        "score":80,
        "severity":"Critical"
    },

    "mitre":
    {
        "tactic":"Credential Access",
        "technique":"Brute Force",
        "id":"T1110"
    }

}



manager = AlertManager()


alert = manager.create_alert(
    sample_event
)


print(alert)



report = generate_report(
    alert
)


print("\nReport Created:")
print(report)