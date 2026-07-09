from ollama import chat


class AIEngine:

    def analyze(self, event, raw_event):

        mitre = event.get("mitre", {})
        risk = event.get("risk", {})
        windows_event = event.get("windows_event", {})


        prompt = f"""

You are a Senior SOC Analyst working in an enterprise SOC.

Analyze ONLY the provided evidence.

Rules:
- Do not guess.
- Do not invent malware.
- Do not assume attacker activity.
- Do not change MITRE mapping.
- If information is missing write "Not Present".


====================================================
EVENT DATA
====================================================

Event ID:
{event.get("event_id")}

Computer:
{event.get("computer")}

User:
{event.get("account")}

Process:
{event.get("process")}


Windows Event Information:

Title:
{windows_event.get("title")}

Description:
{windows_event.get("description")}


Risk Score:
{risk.get("score")}

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

Generate a professional SOC investigation report.


====================================================
EVENT SUMMARY
====================================================


Event ID:

Risk Score:

Severity:


Windows Description:

(Write one clear sentence.
Do not copy raw logs.)


====================================================
MITRE ATT&CK
====================================================

Tactic:

Technique:

Technique ID:


====================================================
WHY THIS EVENT OCCURRED
====================================================


Explain based only on evidence.


====================================================
IS THIS SUSPICIOUS?
====================================================


Answer:
Benign / Suspicious / Malicious

Explain why.


====================================================
INVESTIGATION STEPS
====================================================

1.
2.
3.


====================================================
RECOMMENDED ACTIONS
====================================================

1.
2.
3.


====================================================
INDICATORS OF COMPROMISE
====================================================

User:

Process:

Computer:

Event ID:

IP Address:

Command Line:


====================================================
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