import streamlit as st
import sqlite3
import pandas as pd
from ai_engine import AIEngine


st.set_page_config(
    page_title="AI Investigation",
    page_icon="🤖",
    layout="wide"
)



st.title(
    "🤖 AI SOC Investigation Assistant"
)


st.caption(
    "Ask questions about security alerts using your local AI SOC engine"
)



# ======================================
# Load Alerts
# ======================================


def load_alerts():

    conn = sqlite3.connect(
        "soc_alerts.db"
    )


    df = pd.read_sql_query(

        """
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
        """,

        conn

    )


    conn.close()


    return df



df = load_alerts()



if df.empty:

    st.warning(
        "No alerts available"
    )

    st.stop()



# ======================================
# Select Alert
# ======================================


st.subheader(
    "Select Security Alert"
)



alert_id = st.selectbox(

    "Alert ID",

    df["alert_id"].tolist()

)



selected = df[

    df["alert_id"] == alert_id

]



alert = selected.iloc[0].to_dict()



st.json(alert)




# ======================================
# AI Question
# ======================================


st.subheader(
    "Ask AI SOC Analyst"
)



question = st.text_input(

    "Question",

    placeholder=
    "Example: Why is this alert suspicious?"

)



if st.button(
    "Analyze"
):


    ai = AIEngine()



    event = {


        "event_id":
        str(alert.get("event_id")),


        "computer":
        alert.get("host"),


        "account":
        alert.get("user"),


        "process":
        alert.get("process"),


        "risk":
        {

        "score":
        alert.get("risk_score"),

        "severity":
        alert.get("severity")

        },


        "mitre":
        {

        "tactic":
        alert.get("mitre_tactic",
        "Not Present"),

        "technique":
        alert.get("mitre_technique",
        "Not Present"),

        "id":
        alert.get("mitre_id",
        "Not Present")

        }


    }



    prompt_event = f"""

Security Alert:

{event}


Analyst Question:

{question}


Provide a SOC analyst response.

Include:

- Explanation
- Risk
- Investigation steps
- Recommended actions

"""


    result = ai.analyze(

        event,

        prompt_event

    )


    st.subheader(
        "AI Investigation Result"
    )


    st.markdown(
        result
    )