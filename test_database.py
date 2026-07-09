from alert_database import create_database, insert_alert, get_alerts


create_database()


sample_alert = {

"alert_id":"SOC-TEST-001",

"timestamp":"2026-07-09",

"event_id":"4625",

"severity":"High",

"risk_score":80,

"user":"admin",

"host":"Rachana",

"mitre":
{
"id":"T1110"
},

"correlation":
{
"alert":"Brute Force"
}

}


insert_alert(sample_alert)


print(get_alerts())