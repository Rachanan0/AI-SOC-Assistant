import sqlite3
import json


DB_NAME = "soc_alerts.db"


def create_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        alert_id TEXT,

        timestamp TEXT,

        event_id TEXT,

        severity TEXT,

        risk_score INTEGER,

        user TEXT,

        host TEXT,

        mitre TEXT,

        correlation TEXT

    )
    """)


    conn.commit()

    conn.close()



def insert_alert(alert):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()


    cursor.execute("""
    INSERT INTO alerts
    (
    alert_id,
    timestamp,
    event_id,
    severity,
    risk_score,
    user,
    host,
    mitre,
    correlation
    )

    VALUES (?,?,?,?,?,?,?,?,?)

    """,

    (

    alert["alert_id"],
    alert["timestamp"],
    alert["event_id"],
    alert["severity"],
    alert["risk_score"],
    alert["user"],
    alert["host"],
    json.dumps(alert["mitre"]),
    json.dumps(alert["correlation"])

    ))


    conn.commit()

    conn.close()



def get_alerts():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()


    cursor.execute(
        "SELECT * FROM alerts ORDER BY id DESC"
    )


    data = cursor.fetchall()


    conn.close()


    return data