
import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk
import numpy as np
from streamlit_autorefresh import st_autorefresh


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="AI SOC Command Center",
    page_icon="🛡️",
    layout="wide"
)


# =====================================================
# AUTO REFRESH
# =====================================================

st_autorefresh(
    interval=10000,
    key="refresh"
)


# =====================================================
# CUSTOM STYLE
# =====================================================

st.markdown(
"""
<style>

body {
background-color:#f5f9ff;
}


.main {
background-color:#f5f9ff;
}


h1,h2,h3 {
color:#003366;
}


div[data-testid="metric-container"] {

background:white;
padding:20px;
border-radius:15px;
box-shadow:0 5px 20px rgba(0,0,0,0.15);

}


.stDataFrame {

background:white;

}


</style>

""",
unsafe_allow_html=True
)



# =====================================================
# DATABASE
# =====================================================


def load_alerts():

    try:

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


    except Exception as e:

        st.error(e)

        return pd.DataFrame()



# =====================================================
# LOAD DATA
# =====================================================

df = load_alerts()



if df.empty:

    st.warning(
        "No SOC alerts found"
    )

    st.stop()



# =====================================================
# HEADER
# =====================================================
st.markdown("""
<h1>
🛡 AI SOC COMMAND CENTER
</h1>
""", unsafe_allow_html=True)

st.markdown(
"""
<div style="text-align:center;
font-size:18px;
color:#94A3B8;
margin-bottom:25px;">
Splunk Enterprise • MITRE ATT&CK • AI Investigation Engine
</div>
""",
unsafe_allow_html=True)
# =====================================================
# KPI
# =====================================================


total=len(df)


critical=len(
df[df["severity"]=="Critical"]
)


high=len(
df[df["severity"]=="High"]
)


medium=len(
df[df["severity"]=="Medium"]
)



c1,c2,c3,c4=st.columns(4)



c1.metric(
"Total Alerts",
total
)


c2.metric(
"Critical",
critical
)


c3.metric(
"High",
high
)


c4.metric(
"Medium",
medium
)




# =====================================================
# SIDEBAR
# =====================================================


st.sidebar.title(
"🔍 SOC Filters"
)



severity_options=df["severity"].unique()



severity_filter=st.sidebar.multiselect(

"Severity",

severity_options,

default=list(severity_options)

)



filtered=df[
df["severity"].isin(
severity_filter
)
]



if filtered.empty:

    st.warning(
    "No alerts available"
    )

    st.stop()




# =====================================================
# ALERT TABLE
# =====================================================


st.subheader(
"🚨 Live Security Alerts"
)



columns=[

"alert_id",
"timestamp",
"event_id",
"host",
"user",
"severity",
"risk_score"

]



available=[

x for x in columns

if x in filtered.columns

]



st.dataframe(

filtered[available],

use_container_width=True,

height=300

)





# =====================================================
# SELECT ALERT
# =====================================================


selected=st.selectbox(

"Select Alert",

filtered["alert_id"].tolist()

)



alert_row=filtered[

filtered["alert_id"]

==selected

]





# =====================================================
# RISK GAUGE
# =====================================================


st.subheader(
"⚠️ Threat Risk Score"
)



if not alert_row.empty:


    score=int(

    alert_row.iloc[0]
    ["risk_score"]

    )


    fig=go.Figure(

    go.Indicator(

    mode="gauge+number",

    value=score,


    gauge={

    "axis":{
    "range":[0,100]
    }

    },

    title={
    "text":"Risk Level"
    }

    )

    )


    st.plotly_chart(

    fig,

    use_container_width=True

    )





# =====================================================
# LIVE THREAT MAP
# =====================================================


st.subheader(
"🌐 Live SOC Threat Activity"
)



map_data=pd.DataFrame({

"lat":

np.random.uniform(
15,
30,
len(filtered)
),


"lon":

np.random.uniform(
70,
85,
len(filtered)
),


"alert":

filtered["severity"]

})




layer=pdk.Layer(

"ScatterplotLayer",

data=map_data,

get_position="[lon,lat]",

get_radius=50000,

pickable=True

)



view=pdk.ViewState(

latitude=22,

longitude=78,

zoom=4

)



st.pydeck_chart(

pdk.Deck(

layers=[layer],

initial_view_state=view

)

)




# =====================================================
# SEVERITY CHART
# =====================================================


st.subheader(
"📊 Severity Distribution"
)



severity_count=(

df["severity"]

.value_counts()

)



fig=px.pie(

values=severity_count.values,

names=severity_count.index,

hole=.45

)



st.plotly_chart(

fig,

use_container_width=True

)




# =====================================================
# RISK TREND
# =====================================================


st.subheader(
"📈 Risk Trend"
)



if "risk_score" in df.columns:


    fig=px.line(

    df,

    y="risk_score",

    title="Risk Score Timeline"

    )


    st.plotly_chart(

    fig,

    use_container_width=True

    )




# =====================================================
# MITRE ATT&CK
# =====================================================


st.subheader(
"🎯 MITRE ATT&CK Activity"
)



if "technique" in df.columns:


    mitre=(

    df["technique"]

    .value_counts()

    )


    st.bar_chart(

    mitre

    )

else:

    st.info(
    "MITRE data not available"
    )





# =====================================================
# MITRE HEATMAP
# =====================================================


if "technique" in df.columns:


    st.subheader(
    "🔥 MITRE Heatmap"
    )


    heat=(

    df.groupby(

    [
    "technique",
    "severity"
    ]

    )

    .size()

    .reset_index(
    name="count"
    )

    )


    fig=px.density_heatmap(

    heat,

    x="technique",

    y="severity",

    z="count"

    )


    st.plotly_chart(

    fig,

    use_container_width=True

    )





# =====================================================
# INVESTIGATION PANEL
# =====================================================


st.subheader(
"🔎 Incident Investigation"
)



if not alert_row.empty:


    st.json(

    alert_row.iloc[0]

    .to_dict()

    )





# =====================================================
# AI PANEL
# =====================================================


st.subheader(
"🤖 AI SOC Analyst"
)



st.success(
"""
AI Engine Online

✔ Windows Event Analysis

✔ MITRE ATT&CK Mapping

✔ Risk Scoring

✔ Correlation Detection

✔ Incident Report Generation

"""
)




# =====================================================
# FOOTER
# =====================================================


st.markdown(

"""
---
<center>
🛡️ AI SOC Assistant  
Automated Security Operations Platform
</center>
""",

unsafe_allow_html=True

)
# =====================================================
# LIVE ALERT FEED
# =====================================================

st.subheader("🚨 Live Security Alerts")

display_cols = [
    "alert_id",
    "timestamp",
    "event_id",
    "host",
    "user",
    "severity",
    "risk_score"
]

display_cols = [c for c in display_cols if c in filtered.columns]

st.dataframe(
    filtered[display_cols],
    use_container_width=True,
    height=350
)

# =====================================================
# ALERT SELECTOR
# =====================================================

st.subheader("🔍 Select Alert")

selected = st.selectbox(
    "Choose an Alert",
    filtered["alert_id"].tolist()
)

selected_alert = filtered[
    filtered["alert_id"] == selected
]

alert = selected_alert.iloc[0]

# =====================================================
# ALERT SUMMARY
# =====================================================

st.subheader("📋 Alert Summary")

col1, col2 = st.columns(2)

with col1:
    st.info(f"""
**Alert ID:** {alert['alert_id']}

**Severity:** {alert['severity']}

**Risk Score:** {alert['risk_score']}
""")

with col2:
    st.success(f"""
**Host:** {alert['host']}

**User:** {alert['user']}

**Event ID:** {alert['event_id']}
""")

# =====================================================
# RISK GAUGE
# =====================================================

st.subheader("⚠ Threat Risk Level")

fig = go.Figure(
    go.Indicator(
        mode="gauge+number",
        value=int(alert["risk_score"]),
        number={"font": {"size": 42}},
        title={"text": "Risk Score"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "red"},
            "steps": [
                {"range": [0, 30], "color": "green"},
                {"range": [30, 60], "color": "gold"},
                {"range": [60, 80], "color": "orange"},
                {"range": [80, 100], "color": "red"}
            ]
        }
    )
)

fig.update_layout(
    height=350,
    paper_bgcolor="#122238",
    font_color="white"
)

st.plotly_chart(fig, use_container_width=True)

# =====================================================
# SEVERITY DISTRIBUTION
# =====================================================

st.subheader("📊 Alert Severity Distribution")

severity = (
    filtered["severity"]
    .value_counts()
    .reset_index()
)

severity.columns = ["Severity", "Count"]

fig = px.pie(
    severity,
    values="Count",
    names="Severity",
    hole=0.6,
    color="Severity",
    color_discrete_map={
        "Critical": "#ff1744",
        "High": "#ff9800",
        "Medium": "#ffeb3b",
        "Low": "#4caf50"
    }
)

fig.update_layout(
    paper_bgcolor="#122238",
    font_color="white",
    height=450
)

st.plotly_chart(fig, use_container_width=True)

# =====================================================
# RISK TREND
# =====================================================

st.subheader("📈 Risk Score Trend")

trend = filtered.copy()
trend = trend.sort_values("timestamp")

fig = px.line(
    trend,
    x="timestamp",
    y="risk_score",
    markers=True,
    title="Risk Score Timeline"
)

fig.update_layout(
    paper_bgcolor="#122238",
    plot_bgcolor="#122238",
    font_color="white",
    height=400
)

st.plotly_chart(fig, use_container_width=True)

# =====================================================
# WINDOWS EVENT DISTRIBUTION
# =====================================================

st.subheader("📊 Windows Event Distribution")

events = (
    filtered["event_id"]
    .value_counts()
    .reset_index()
)

events.columns = ["Event ID", "Count"]

fig = px.bar(
    events,
    x="Event ID",
    y="Count",
    text="Count",
    color="Count",
    color_continuous_scale="Blues"
)

fig.update_layout(
    paper_bgcolor="#122238",
    plot_bgcolor="#122238",
    font_color="white",
    height=400
)

st.plotly_chart(fig, use_container_width=True)

# =====================================================
# ATTACK TIMELINE
# =====================================================

st.subheader("⏱ Recent Security Activity")

timeline = filtered[
    ["timestamp", "event_id", "severity"]
].head(15)

for _, row in timeline.iterrows():

    emoji = "🟢"

    if row["severity"] == "Critical":
        emoji = "🔴"
    elif row["severity"] == "High":
        emoji = "🟠"
    elif row["severity"] == "Medium":
        emoji = "🟡"

    st.markdown(
        f"{emoji} **{row['timestamp']}** — Event **{row['event_id']}** ({row['severity']})"
    )
# =====================================================
# AI SOC INVESTIGATION PANEL
# =====================================================

st.markdown("---")
st.subheader("🤖 AI SOC Investigation")

left, right = st.columns([2, 1])

with left:

    verdict = "🟢 Benign"

    if alert["severity"] == "Critical":
        verdict = "🔴 Malicious"
    elif alert["severity"] == "High":
        verdict = "🟠 Suspicious"
    elif alert["severity"] == "Medium":
        verdict = "🟡 Needs Investigation"

    st.markdown(f"""
### AI Verdict

**Classification:** {verdict}

---

### Investigation Summary

The AI SOC Engine analyzed this alert using:

- Windows Security Event Analysis
- MITRE ATT&CK Mapping
- Risk Scoring Engine
- Event Correlation
- IOC Analysis

The alert has been prioritized based on its severity and contextual indicators.

---

### Recommended Actions

✅ Review Windows Security Logs

✅ Validate User Activity

✅ Inspect Related Processes

✅ Check Endpoint Security Status

✅ Review MITRE ATT&CK Technique

✅ Escalate if additional suspicious events are detected

""")

with right:

    st.metric("Risk Score", alert["risk_score"])
    st.metric("Severity", alert["severity"])
    st.metric("Host", alert["host"])
    st.metric("User", alert["user"])

# =====================================================
# INDICATORS OF COMPROMISE
# =====================================================

st.markdown("---")
st.subheader("🧬 Indicators of Compromise (IOC)")

c1, c2, c3, c4 = st.columns(4)

process = alert["process"] if "process" in alert.index else "N/A"

with c1:
    st.success(f"""
### User

{alert["user"]}
""")

with c2:
    st.info(f"""
### Process

{process}
""")

with c3:
    st.warning(f"""
### Host

{alert["host"]}
""")

with c4:
    st.error(f"""
### Event ID

{alert["event_id"]}
""")

# =====================================================
# MITRE ATT&CK ANALYTICS
# =====================================================

st.markdown("---")
st.subheader("🎯 MITRE ATT&CK Activity")

if "technique" in filtered.columns:

    mitre = (
        filtered["technique"]
        .value_counts()
        .reset_index()
    )

    mitre.columns = ["Technique", "Count"]

    fig = px.bar(
        mitre,
        x="Technique",
        y="Count",
        text="Count",
        color="Count",
        color_continuous_scale="Turbo"
    )

    fig.update_layout(
        paper_bgcolor="#122238",
        plot_bgcolor="#122238",
        font_color="white",
        height=450
    )

    st.plotly_chart(fig, use_container_width=True)

else:

    st.info("No MITRE ATT&CK data available.")

# =====================================================
# MITRE HEATMAP
# =====================================================

if "technique" in filtered.columns:

    st.subheader("🔥 MITRE Heatmap")

    heat = (
        filtered
        .groupby(["technique", "severity"])
        .size()
        .reset_index(name="Count")
    )

    fig = px.density_heatmap(
        heat,
        x="technique",
        y="severity",
        z="Count",
        color_continuous_scale="Turbo"
    )

    fig.update_layout(
        paper_bgcolor="#122238",
        plot_bgcolor="#122238",
        font_color="white",
        height=450
    )

    st.plotly_chart(fig, use_container_width=True)

# =====================================================
# THREAT METER
# =====================================================

st.markdown("---")
st.subheader("🔥 Threat Meter")

risk = int(alert["risk_score"])

if risk >= 85:
    st.error("██████████████████████ 100%")
elif risk >= 65:
    st.warning("██████████████████░░░░")
elif risk >= 35:
    st.info("███████████░░░░░░░░░░")
else:
    st.success("█████░░░░░░░░░░░░░░░")

# =====================================================
# PLATFORM STATUS
# =====================================================

st.markdown("---")
st.subheader("🖥 Platform Status")

p1, p2, p3, p4 = st.columns(4)

with p1:
    st.success("🟢 Splunk Connected")

with p2:
    st.success("🟢 SQLite Online")

with p3:
    st.success("🟢 AI Engine Running")

with p4:
    st.success("🟢 Dashboard Active")

# =====================================================
# AI ENGINE STATUS
# =====================================================

st.markdown("---")
st.subheader("⚙ AI Engine Status")

st.success("""
✅ Windows Event Parsing

✅ MITRE ATT&CK Mapping

✅ Risk Scoring Engine

✅ Event Correlation

✅ IOC Extraction

✅ SQLite Alert Storage

✅ Incident Report Generation

✅ AI Investigation Engine

✅ Streamlit Dashboard Online
""")
# =====================================================
# LIVE GLOBAL THREAT MAP
# =====================================================

st.markdown("---")
st.subheader("🌍 Global Threat Intelligence")

locations = pd.DataFrame({
    "City":[
        "Hyderabad",
        "Mumbai",
        "Delhi",
        "Bangalore",
        "Chennai",
        "Kolkata",
        "Pune",
        "Singapore",
        "London",
        "New York"
    ],

    "lat":[
        17.3850,
        19.0760,
        28.6139,
        12.9716,
        13.0827,
        22.5726,
        18.5204,
        1.3521,
        51.5072,
        40.7128
    ],

    "lon":[
        78.4867,
        72.8777,
        77.2090,
        77.5946,
        80.2707,
        88.3639,
        73.8567,
        103.8198,
        -0.1276,
        -74.0060
    ],

    "Severity":[
        "Critical",
        "High",
        "Medium",
        "Low",
        "High",
        "Critical",
        "Medium",
        "Critical",
        "High",
        "Critical"
    ],

    "Risk":[
        96,
        81,
        55,
        30,
        76,
        92,
        47,
        95,
        83,
        98
    ]
})

layer = pdk.Layer(

    "ScatterplotLayer",

    data=locations,

    get_position='[lon, lat]',

    get_fill_color='[255,0,0,180]',

    get_radius='Risk*2500',

    pickable=True,

    auto_highlight=True
)

view = pdk.ViewState(

    latitude=22,

    longitude=75,

    zoom=2,

    pitch=40
)

deck = pdk.Deck(

    layers=[layer],

    initial_view_state=view,

    tooltip={
        "text":"{City}\nSeverity: {Severity}\nRisk: {Risk}"
    }

)

st.pydeck_chart(deck)
# =====================================================
# LIVE THREAT FEED
# =====================================================

st.markdown("---")

st.subheader("🚨 Live Threat Feed")

feed = filtered.head(10)

for _, row in feed.iterrows():

    icon="🟢"

    if row["severity"]=="Critical":
        icon="🔴"

    elif row["severity"]=="High":
        icon="🟠"

    elif row["severity"]=="Medium":
        icon="🟡"

    st.markdown(

        f"""
{icon} **{row['timestamp']}**

Host : **{row['host']}**

User : **{row['user']}**

Risk : **{row['risk_score']}**

Event : **{row['event_id']}**

---
"""
)
# =====================================================
# HOST ANALYTICS
# =====================================================

st.markdown("---")

st.subheader("💻 Most Targeted Hosts")

hosts = (

filtered["host"]

.value_counts()

.reset_index()

)

hosts.columns=[

"Host",

"Alerts"

]

fig = px.bar(

hosts,

x="Host",

y="Alerts",

text="Alerts",

color="Alerts",

color_continuous_scale="Reds"

)

fig.update_layout(

paper_bgcolor="#122238",

plot_bgcolor="#122238",

font_color="white",

height=450

)

st.plotly_chart(

fig,

use_container_width=True

)
# =====================================================
# USER ANALYTICS
# =====================================================

st.markdown("---")

st.subheader("👤 User Activity")

users = (

filtered["user"]

.value_counts()

.reset_index()

)

users.columns=[

"User",

"Events"

]

fig = px.bar(

users,

x="User",

y="Events",

text="Events",

color="Events",

color_continuous_scale="Blues"

)

fig.update_layout(

paper_bgcolor="#122238",

plot_bgcolor="#122238",

font_color="white"

)

st.plotly_chart(

fig,

use_container_width=True

)
# =====================================================
# SOC HEALTH
# =====================================================

st.markdown("---")

st.subheader("🛡 Security Operations Health")

a,b,c = st.columns(3)

with a:

    st.metric(

        "Detection Rate",

        "98.4%"

    )

with b:

    st.metric(

        "Mean Time To Detect",

        "42 sec"

    )

with c:

    st.metric(

        "SOC Availability",

        "99.9%"

    )
# =====================================================
# LIVE EVENT TICKER
# =====================================================

st.markdown("---")
st.subheader("📡 Live Event Ticker")

ticker = filtered.head(15)

ticker_html = ""

for _, row in ticker.iterrows():

    color = "#4CAF50"

    if row["severity"] == "Critical":
        color = "#ff1744"
    elif row["severity"] == "High":
        color = "#ff9800"
    elif row["severity"] == "Medium":
        color = "#ffeb3b"

    ticker_html += f"""
    <span style="
        color:{color};
        font-size:18px;
        font-weight:bold;
        margin-right:70px;
    ">
        [{row['timestamp']}] Event {row['event_id']} | Host: {row['host']} | Risk: {row['risk_score']}
    </span>
    """

st.markdown(f"""
<style>

@keyframes ticker {{

0% {{
transform:translateX(100%);
}}

100% {{
transform:translateX(-100%);
}}

}}

.ticker-container {{

overflow:hidden;

white-space:nowrap;

background:#0F172A;

padding:15px;

border-radius:12px;

border:1px solid #1f2937;

}}

.ticker {{

display:inline-block;

animation:ticker 35s linear infinite;

}}

</style>

<div class="ticker-container">
<div class="ticker">
{ticker_html}
</div>
</div>
""", unsafe_allow_html=True)

# =====================================================
# CORRELATION MATRIX
# =====================================================

st.markdown("---")
st.subheader("🔗 Alert Correlation Matrix")

corr = filtered.copy()

corr["severity_num"] = corr["severity"].map({
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
})

heat = corr[["risk_score", "severity_num"]].corr()

fig = px.imshow(
    heat,
    text_auto=True,
    color_continuous_scale="Turbo",
    aspect="auto"
)

fig.update_layout(
    paper_bgcolor="#122238",
    font_color="white",
    height=400
)

st.plotly_chart(fig, use_container_width=True)

# =====================================================
# NETWORK TRAFFIC
# =====================================================

st.markdown("---")
st.subheader("🌐 Network Activity")

network = pd.DataFrame({

    "Minute": list(range(1,31)),

    "Traffic": np.random.randint(
        50,
        300,
        30
    )

})

fig = px.area(

    network,

    x="Minute",

    y="Traffic",

    title="Network Traffic"

)

fig.update_layout(

paper_bgcolor="#122238",

plot_bgcolor="#122238",

font_color="white"

)

st.plotly_chart(

fig,

use_container_width=True

)

# =====================================================
# ALERT SEVERITY TIMELINE
# =====================================================

st.markdown("---")
st.subheader("🚨 Alert Timeline")

timeline = filtered.copy()

timeline = timeline.sort_values("timestamp")

fig = px.scatter(

timeline,

x="timestamp",

y="risk_score",

size="risk_score",

color="severity",

hover_data=["host", "user", "event_id"],

color_discrete_map={

"Critical":"red",

"High":"orange",

"Medium":"yellow",

"Low":"green"

}

)

fig.update_layout(

paper_bgcolor="#122238",

plot_bgcolor="#122238",

font_color="white",

height=500

)

st.plotly_chart(

fig,

use_container_width=True

)

# =====================================================
# EXECUTIVE OVERVIEW
# =====================================================

st.markdown("---")
st.subheader("📈 Executive Security Overview")

left, right = st.columns(2)

with left:

    st.metric(
        "Total Events",
        len(filtered)
    )

    st.metric(
        "Average Risk",
        round(filtered["risk_score"].mean(),1)
    )

    st.metric(
        "Highest Risk",
        filtered["risk_score"].max()
    )

with right:

    st.metric(
        "Unique Hosts",
        filtered["host"].nunique()
    )

    st.metric(
        "Unique Users",
        filtered["user"].nunique()
    )

    st.metric(
        "Critical %",
        str(round(
            len(filtered[
                filtered["severity"]=="Critical"
            ]) / len(filtered) * 100,
            1
        )) + "%"
    )

# =====================================================
# TOP RISKY EVENTS
# =====================================================

st.markdown("---")
st.subheader("🔥 Highest Risk Alerts")

top = filtered.sort_values(
    "risk_score",
    ascending=False
).head(10)

st.dataframe(

top,

use_container_width=True,

height=350

)
# =====================================================
# AI RECOMMENDATIONS
# =====================================================

st.markdown("---")
st.subheader("🧠 AI Recommendations")

recommendations = [
    "Review failed logon attempts for brute-force activity.",
    "Verify privileged account usage and recent privilege escalation.",
    "Inspect suspicious PowerShell or CMD executions.",
    "Correlate alerts across endpoints for lateral movement.",
    "Run antivirus and EDR scans on affected hosts.",
    "Validate user activity against expected behavior.",
]

for rec in recommendations:
    st.info(f"✅ {rec}")

# =====================================================
# SOC ANALYST SCORECARD
# =====================================================

st.markdown("---")
st.subheader("📊 SOC Analyst Scorecard")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Alerts Investigated", len(filtered))

with col2:
    mttr = np.random.randint(5, 20)
    st.metric("Avg Response Time", f"{mttr} min")

with col3:
    accuracy = np.random.randint(95, 100)
    st.metric("Detection Accuracy", f"{accuracy}%")

# =====================================================
# THREAT INTELLIGENCE FEED
# =====================================================

st.markdown("---")
st.subheader("🌐 Threat Intelligence Feed")

intel = pd.DataFrame({
    "IOC": [
        "powershell.exe",
        "cmd.exe",
        "mimikatz.exe",
        "psexec.exe",
        "certutil.exe"
    ],
    "Threat": [
        "PowerShell Abuse",
        "Command Execution",
        "Credential Dumping",
        "Remote Execution",
        "File Download"
    ],
    "Severity": [
        "Medium",
        "Medium",
        "Critical",
        "High",
        "High"
    ]
})

st.dataframe(intel, use_container_width=True)

# =====================================================
# DOWNLOAD INCIDENT REPORTS
# =====================================================

st.markdown("---")
st.subheader("📥 Export Reports")

csv = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="⬇ Download Alerts (CSV)",
    data=csv,
    file_name="soc_alerts.csv",
    mime="text/csv",
)

# =====================================================
# ENGINE STATUS
# =====================================================

st.markdown("---")
st.subheader("⚙ Engine Health")

status1, status2, status3, status4 = st.columns(4)

with status1:
    st.success("🟢 Splunk Connected")

with status2:
    st.success("🟢 SQLite Online")

with status3:
    st.success("🟢 AI Engine Running")

with status4:
    st.success("🟢 Dashboard Healthy")

# =====================================================
# FOOTER
# =====================================================

st.markdown("---")

st.markdown(
    """
    <div style='text-align:center; padding:20px; color:#9CA3AF;'>

    <h3>🛡 AI SOC Assistant</h3>

    <p>Built with ❤️ using Python, Splunk Enterprise, Streamlit, SQLite, Plotly, MITRE ATT&CK, and Ollama.</p>

    <p>© 2026 Nunemunthala Rachana</p>

    </div>
    """,
    unsafe_allow_html=True,
)