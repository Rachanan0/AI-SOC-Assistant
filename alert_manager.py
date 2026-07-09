from datetime import datetime
import uuid

from alert_database import insert_alert


class AlertManager:


    def create_alert(self, event, correlation=None):

        alert = {

            "alert_id":
            "SOC-" + datetime.now().strftime("%Y%m%d-%H%M%S"),


            "timestamp":
            datetime.now().isoformat(),


            "event_id":
            event.get("event_id"),


            "host":
            event.get("computer"),


            "user":
            event.get("account"),


            "process":
            event.get("process"),


            "severity":
            event.get("risk", {}).get("severity"),


            "risk_score":
            event.get("risk", {}).get("score"),


            "mitre":
            event.get("mitre"),


            "correlation":
            correlation

        }


        # Save alert into SQLite database
        insert_alert(alert)


        return alert