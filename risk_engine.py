# risk_engine.py

def calculate_risk(event):

    event_id = event.get("event_id", "")
    process = event.get("process", "").lower()
    account = event.get("account", "").upper()
    privileges = event.get("privileges", "")
    commandline = event.get("commandline", "").lower()

    # ------------------------------------
    # Base Risk Score
    # ------------------------------------

    base_scores = {
        "4624": 10,   # Successful Logon
        "4625": 45,   # Failed Logon
        "4672": 65,   # Special Privileges Assigned
        "4688": 70,   # Process Creation
        "4698": 80,   # Scheduled Task Created
        "4720": 75,   # User Account Created
        "4726": 75,   # User Account Deleted
        "4732": 70,   # Added to Local Group
        "4768": 35,   # Kerberos TGT Request
        "4769": 35,   # Kerberos Service Ticket
        "4798": 20,   # Group Enumeration
        "5061": 25,   # Cryptographic Operation
        "5379": 40    # Credential Manager Read
    }

    score = base_scores.get(event_id, 20)

    # ------------------------------------
    # Dangerous Processes
    # ------------------------------------

    dangerous_processes = {
        "powershell.exe": 15,
        "cmd.exe": 10,
        "wmic.exe": 15,
        "psexec": 25,
        "mimikatz": 50,
        "procdump": 40,
        "rundll32.exe": 15,
        "regsvr32.exe": 15,
        "certutil.exe": 20,
        "bitsadmin.exe": 20,
        "mshta.exe": 25,
        "cscript.exe": 20,
        "wscript.exe": 20,
        "net.exe": 15,
        "net1.exe": 15
    }

    for proc, value in dangerous_processes.items():
        if proc in process:
            score += value

    # ------------------------------------
    # Dangerous Command Lines
    # ------------------------------------

    dangerous_commands = {
        "-enc": 30,
        "-encodedcommand": 30,
        "downloadstring": 30,
        "invoke-expression": 35,
        "iex": 35,
        "whoami": 5,
        "net user": 15,
        "net localgroup": 20,
        "vssadmin": 25,
        "bcdedit": 25
    }

    for cmd, value in dangerous_commands.items():
        if cmd in commandline:
            score += value

    # ------------------------------------
    # SYSTEM Account
    # ------------------------------------

    if account == "SYSTEM":
        score += 10

    # ------------------------------------
    # Built-in Administrator
    # ------------------------------------

    if account == "ADMINISTRATOR":
        score += 10

    # ------------------------------------
    # High Privileges
    # ------------------------------------

    high_privileges = [
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeTcbPrivilege",
        "SeLoadDriverPrivilege",
        "SeBackupPrivilege"
    ]

    for privilege in high_privileges:
        if privilege in privileges:
            score += 10

    # ------------------------------------
    # Cap Score
    # ------------------------------------

    score = min(score, 100)

    # ------------------------------------
    # Severity
    # ------------------------------------

    if score >= 85:
        severity = "Critical"
    elif score >= 65:
        severity = "High"
    elif score >= 35:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity
    }