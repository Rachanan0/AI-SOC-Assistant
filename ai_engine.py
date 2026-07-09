from ollama import chat


class AIEngine:

    def analyze(self, event, raw_event, correlation=None):

        mitre = event.get("mitre", {})
        risk = event.get("risk", {})
        windows_event = event.get("windows_event", {})


        prompt = f"""

You are a Senior SOC Analyst working in an enterprise Security Operations Center.

Your task is to analyze Windows Security Events.

Follow these rules strictly:

- Analyze ONLY provided evidence.
- Do not guess.
- Do not invent malware.
- Do not assume attacker activity.
- MITRE ATT&CK mapping indicates possible behavior, NOT confirmed attack.
- Risk score is calculated by the detection engine.
- If information is missing write "Not Present".
- A normal Windows activity should be classified as Benign.


====================================================
EVENT INFORMATION
====================================================

Event ID:
{event.get("event_id")}

Computer:
{event.get("computer")}

User:
{event.get("account")}

Process:
{event.get("process")}


Windows Event:

Title:
{windows_event.get("title")}

Description:
{windows_event.get("description")}


Risk Score:
{risk.get("score")}/100

Severity:
{risk.get("severity")}


====================================================
MITRE ATT&CK
====================================================

Tactic:
{mitre.get("tactic")}

Technique:
{mitre.get("technique")}

Technique ID:
{mitre.get("id")}


====================================================
CORRELATION INFORMATION
====================================================

{correlation if correlation else "No related events detected."}


====================================================
SOC INVESTIGATION REPORT
====================================================


EVENT SUMMARY
====================================================

Event ID:

Risk Score:

Severity:

Windows Description:


MITRE ATT&CK
====================================================

Tactic:

Technique:

Technique ID:


WHY THIS EVENT OCCURRED
====================================================

Explain the possible reason this event occurred.

Use only available evidence.


IS THIS SUSPICIOUS?
====================================================

Answer:

Benign / Suspicious / Malicious


Reason:

Classify based on:

Benign:
- Normal Windows activity
- Legitimate system process
- Expected user action

Suspicious:
- Unusual behavior
- Unknown process
- Multiple related events
- Abnormal account activity

Malicious:
- Strong evidence of attack
- Malware indicators
- Confirmed abuse


INVESTIGATION STEPS
====================================================

1.

2.

3.



RECOMMENDED ACTIONS
====================================================

1.

2.

3.



INDICATORS OF COMPROMISE
====================================================

User:

Process:

Computer:

Event ID:

IP Address:

Command Line:



SOC ANALYST VERDICT
====================================================

(Benign / Suspicious / Malicious)


"""


        response = chat(
            model="gemma3:4b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )


        return response["message"]["content"]