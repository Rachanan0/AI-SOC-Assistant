import json
from datetime import datetime


def generate_report(alert):


    filename = (
        "reports/" +
        alert["alert_id"] +
        ".json"
    )


    with open(
        filename,
        "w"
    ) as file:

        json.dump(
            alert,
            file,
            indent=4
        )


    return filename