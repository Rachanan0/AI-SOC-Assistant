from datetime import datetime


class AlertManager:


    def create_alert(self, event, correlation=None):

        alert = {}

        alert["alert_id"] = (
            "SOC-" +
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )


        alert["timestamp"] = datetime.now().isoformat()


        alert["event_id"] = event.get(
            "event_id",
            "Unknown"
        )


        alert["host"] = event.get(
            "computer",
            "Unknown"
        )


        alert["user"] = event.get(
            "account",
            "Unknown"
        )


        alert["process"] = event.get(
            "process",
            "Unknown"
        )


        alert["severity"] = event.get(
            "risk",
            {}
        ).get(
            "severity",
            "Unknown"
        )


        alert["risk_score"] = event.get(
            "risk",
            {}
        ).get(
            "score",
            0
        )


        alert["mitre"] = event.get(
            "mitre",
            {}
        )


        alert["correlation"] = correlation


        return alert