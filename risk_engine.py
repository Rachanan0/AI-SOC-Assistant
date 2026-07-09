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

        "4624": 5,     # Successful Logon
        "4625": 40,    # Failed Logon
        "4672": 30,    # Special Privileges Assigned
        "4688": 50,    # Process Creation
        "4698": 70,    # Scheduled Task
        "4720": 70,    # User Created
        "4726": 70,    # User Deleted
        "4732": 60,    # Added Group Member
        "4768": 25,
        "4769": 25,
        "4798": 15,
        "5061": 20,
        "5379": 40
    }


    score = base_scores.get(event_id,20)



    # ------------------------------------
    # Suspicious Processes
    # ------------------------------------

    dangerous_processes = {

        "powershell.exe":20,
        "cmd.exe":15,
        "wmic.exe":20,
        "psexec":30,
        "mimikatz":50,
        "procdump":40,
        "rundll32.exe":20,
        "regsvr32.exe":20,
        "certutil.exe":25,
        "mshta.exe":30,
        "bitsadmin.exe":25

    }


    for proc,value in dangerous_processes.items():

        if proc in process:
            score += value



    # ------------------------------------
    # Suspicious Commands
    # ------------------------------------

    dangerous_commands = {


        "-enc":30,
        "-encodedcommand":30,
        "downloadstring":30,
        "invoke-expression":30,
        "iex":30,
        "net user":20,
        "net localgroup":20,
        "vssadmin":25,
        "bcdedit":25

    }


    for cmd,value in dangerous_commands.items():

        if cmd in commandline:
            score += value




    # ------------------------------------
    # SYSTEM Account Handling
    # ------------------------------------

    # SYSTEM alone is normal
    # Add risk only when combined with suspicious activity

    if account == "SYSTEM":

        if event_id in ["4688","4698"]:

            score += 15




    # ------------------------------------
    # Administrator Account
    # ------------------------------------

    if account == "ADMINISTRATOR":

        score += 10



    # ------------------------------------
    # Privilege Abuse Detection
    # ------------------------------------

    dangerous_privileges = [

        "SeDebugPrivilege",
        "SeLoadDriverPrivilege"

    ]


    for privilege in dangerous_privileges:

        if privilege in privileges:

            score += 15




    # ------------------------------------
    # Correlation Boost
    # ------------------------------------

    if event.get("correlation"):

        score += 20




    # ------------------------------------
    # Maximum Score
    # ------------------------------------

    score = min(score,100)




    # ------------------------------------
    # Severity
    # ------------------------------------

    if score >= 85:

        severity="Critical"

    elif score >=65:

        severity="High"

    elif score >=35:

        severity="Medium"

    else:

        severity="Low"



    return {

        "score":score,
        "severity":severity

    }