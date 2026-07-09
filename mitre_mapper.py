# mitre_mapper.py

MITRE_MAPPING = {

    "4624": {
        "tactic": "Initial Access",
        "technique": "Valid Accounts",
        "id": "T1078"
    },

    "4625": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },

    "4672": {
        "tactic": "Privilege Escalation",
        "technique": "Valid Accounts",
        "id": "T1078"
    },

    "4688": {
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "id": "T1059"
    },

    "4698": {
        "tactic": "Persistence",
        "technique": "Scheduled Task",
        "id": "T1053.005"
    },

    "4720": {
        "tactic": "Persistence",
        "technique": "Create Account",
        "id": "T1136"
    },

    "4726": {
        "tactic": "Defense Evasion",
        "technique": "Delete Account",
        "id": "T1531"
    },

    "4732": {
        "tactic": "Privilege Escalation",
        "technique": "Add User to Group",
        "id": "T1098"
    },

    "4768": {
        "tactic": "Credential Access",
        "technique": "Kerberos Authentication",
        "id": "T1558"
    },

    "4769": {
        "tactic": "Credential Access",
        "technique": "Kerberoasting",
        "id": "T1558.003"
    },

    "4771": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },

    "4798": {
        "tactic": "Discovery",
        "technique": "Account Discovery",
        "id": "T1087"
    },

    "5061": {
        "tactic": "Credential Access",
        "technique": "Cryptographic Key Access",
        "id": "T1555"
    },

    "5379": {
        "tactic": "Credential Access",
        "technique": "Credentials from Password Stores",
        "id": "T1555"
    },

    "1102": {
        "tactic": "Defense Evasion",
        "technique": "Clear Windows Event Logs",
        "id": "T1070.001"
    },

    "1100": {
        "tactic": "Defense Evasion",
        "technique": "Indicator Removal",
        "id": "T1070"
    },

    "4719": {
        "tactic": "Defense Evasion",
        "technique": "Modify System Firewall",
        "id": "T1562.004"
    },

    "7045": {
        "tactic": "Persistence",
        "technique": "Create or Modify System Process",
        "id": "T1543.003"
    }

}


def get_mitre(event_id):
    """
    Returns MITRE ATT&CK mapping for a Windows Event ID.
    """

    return MITRE_MAPPING.get(
        str(event_id),
        {
            "tactic": "Unknown",
            "technique": "Unknown",
            "id": "Unknown"
        }
    )