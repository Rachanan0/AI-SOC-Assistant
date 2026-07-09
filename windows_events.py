WINDOWS_EVENTS = {
    "4798": {
        "title": "Local Group Membership Enumeration",
        "description": "A user's local group membership was enumerated."
    },

    "4672": {
        "title": "Special Privileges Assigned",
        "description": "Special privileges were assigned to a new logon."
    },

    "4624": {
        "title": "Successful Logon",
        "description": "An account successfully logged on."
    },

    "4625": {
        "title": "Failed Logon",
        "description": "An account failed to log on."
    },

    "4688": {
        "title": "Process Creation",
        "description": "A new process was created."
    },

    "5379": {
        "title": "Credential Manager Access",
        "description": "Credential Manager credentials were read."
    },

    "5061": {
        "title": "Cryptographic Operation",
        "description": "A cryptographic key operation occurred."
    }
}


def get_windows_event(event_id):
    return WINDOWS_EVENTS.get(
        event_id,
        {
            "title": "Unknown Event",
            "description": "Unknown Windows Security Event."
        }
    )