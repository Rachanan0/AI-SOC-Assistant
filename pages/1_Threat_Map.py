import streamlit as st
import sqlite3
import pandas as pd
import pydeck as pdk
import numpy as np


st.set_page_config(
    page_title="Threat Map",
    page_icon="🌎",
    layout="wide"
)


st.title("🌎 Live SOC Threat Map")



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



# Create simulated locations

map_data = pd.DataFrame({

    "lat":
    np.random.uniform(
        10,
        35,
        len(df)
    ),


    "lon":
    np.random.uniform(
        65,
        95,
        len(df)
    ),


    "severity":
    df["severity"]

})



layer = pdk.Layer(

    "ScatterplotLayer",

    data=map_data,

    get_position="[lon,lat]",

    get_radius=70000,

    pickable=True

)



view = pdk.ViewState(

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



st.subheader(
"🚨 Recent Threat Activity"
)


st.dataframe(

df,

use_container_width=True

)