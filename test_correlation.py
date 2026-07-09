from correlation_engine import correlation_engine


events = [

{
"event_id":"4625",
"account":"admin"
},

{
"event_id":"4625",
"account":"admin"
},

{
"event_id":"4625",
"account":"admin"
},

{
"event_id":"4625",
"account":"admin"
},

{
"event_id":"4625",
"account":"admin"
}

]


alerts = correlation_engine(events)


for alert in alerts:
    print(alert)