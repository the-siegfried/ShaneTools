#!/usr/bin/env python3
"""
cortex_query_runner.py
Cyber Risk Assessment — Palo Alto Networks Cortex XDR Automated Collection Script
Shane D. Shook, PhD (c) 2026  |  Automated by script

Collects four categories of data from Cortex XDR via the public REST API:

  1. XQL queries  (LVL1–LVL5 threat-hunting queries against the xdr_data dataset)
       Uses the async job pattern:
         POST /public_api/v1/xql/start_xql_query           → execution ID
         POST /public_api/v1/xql/get_query_results         → poll until not PENDING
         POST /public_api/v1/xql/get_query_results_stream  → rows beyond the 1,000-row inline cap
  2. Host / endpoint inventory   → HostInventory.csv
       POST /public_api/v1/endpoints/get_endpoint  (paged, 100 per call)
  3. Application inventory       → app-inventory.csv
       XQL against the host_inventory_applications preset
       (requires the Cortex XDR Host Insights add-on)
  4. Management audit log        → MgmtActivity.csv
       POST /public_api/v1/audits/management_logs  (paged, 100 per call)

Writes every result to an individual CSV file in the output directory and
produces a chain-of-custody manifest (JSON + SHA-256), in the same layout as
s1_query_runner.py and CS_query_runner.py.

AUTHENTICATION
  Create an API key in Cortex XDR (Settings → Configurations → Integrations →
  API Keys) with the Instance Administrator role (or a custom role that can run
  XQL queries and read endpoints and audit logs).
    --auth-type standard   Authorization: <key>                       (default)
    --auth-type advanced   Authorization: sha256(key + nonce + ts)  +  x-xdr-nonce, x-xdr-timestamp
  Both send  x-xdr-auth-id: <key id>.  Use the type that matches how the key
  was created.  The key and key ID may also come from the environment
  variables CORTEX_API_KEY and CORTEX_API_KEY_ID, which keeps them out of the
  shell history and process list.

TENANT URL
  --fqdn takes the tenant FQDN shown in the API Keys page "Copy API URL" action,
  e.g.  acme.xdr.us.paloaltonetworks.com  →  https://api-acme.xdr.us.paloaltonetworks.com
  A value that already starts with api- or http(s):// is used as given.

QUOTA
  XQL API queries consume Cortex query quota (remaining quota and per-query cost
  are recorded in the chain-of-custody manifest) and at most four run in
  parallel per tenant.  This script runs queries one at a time.  On a large
  tenant use a shorter --days window, or --only to run a subset.

Usage:
    python cortex_query_runner.py \
        --fqdn        YOUR-TENANT.xdr.us.paloaltonetworks.com \
        --api-key     YOUR_API_KEY \
        --api-key-id  YOUR_API_KEY_ID \
        [--auth-type  standard|advanced] \
        [--days       90] \
        [--output     ./cortex_assessment_output] \
        [--from-date  2026-02-25T00:00:00Z] \
        [--to-date    2026-05-25T23:59:59Z] \
        [--only       Beacons.csv,RmmUse.csv]

    If --from-date / --to-date are omitted the script defaults to the last
    --days days (default 90).  The window applies to XQL event queries and the
    management audit log.  Host and application inventories are point-in-time.

Requirements:
    pip install requests
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import secrets
import string
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cortex_runner")

# ── Constants ─────────────────────────────────────────────────────────────────
POLL_INTERVAL   = 5       # seconds between result polls
POLL_TIMEOUT    = 900     # seconds before giving up on a single XQL query
PAGE_SIZE       = 100     # max rows per page for get_endpoint / management_logs
HTTP_TIMEOUT    = 300     # seconds per HTTP call (result streams can be large)
MAX_RETRIES     = 5       # retries on HTTP 429 / 5xx
API_PREFIX      = "/public_api/v1"
COC_FILENAME    = "chain_of_custody.json"
INVENTORY_PRESET = "host_inventory_applications"

# ── XQL Query catalogue ───────────────────────────────────────────────────────
# Each entry:  (output_csv, risk_level, description, xql_string | None)
#
# The output file names match s1_query_runner.py / CS_query_runner.py so that
# AnalysisPrompt.txt applies unchanged.
#
# Field mapping from SentinelOne / CrowdStrike equivalents (xdr_data dataset):
#   endpoint.name / ComputerName       → agent_hostname
#   event.time / ContextTimeStamp      → _time
#   process creation                   → event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
#   src.process.* (the parent)         → actor_process_image_name / _path / _command_line
#   tgt.process.* (the new process)    → action_process_image_name / _path / _command_line
#   user of the acting process         → actor_effective_username
#   user of the new process            → action_process_username
#   network connection                 → event_type = ENUM.NETWORK  (action_remote_ip, action_remote_port, action_local_ip, action_local_port)
#   DNS lookup                         → dns_query_name != null
#   registry write                     → event_type = ENUM.REGISTRY (action_registry_key_name)
#   file write                         → event_type = ENUM.FILE     (action_file_path, action_file_name)
#   remote thread / injection          → event_type = ENUM.INJECTION (action_remote_process_image_name)
#   driver / module load               → event_type = ENUM.LOAD_IMAGE (action_module_path)
#
# XQL syntax notes:
#   * `config case_sensitive = false` makes string comparisons case-insensitive;
#     regexes additionally carry (?i).
#   * Regex match is  field ~= "regex"  and negated  field !~= "regex".
#   * Inside an XQL string a literal regex backslash is written as four
#     backslashes ("\\\\") and a regex escape such as \. as two ("\\.").
#     Queries below are Python raw strings, so what you see is what XQL receives.
#
# Differences from the S1 / CS catalogues (Cortex XDR does not record the same data):
#   * UPPCount / UPPActivity use process-start activity per user per host as the
#     profile-propagation signal; logon events require Windows Event Log
#     collection, which is not on by default.
#   * CredentialTheft matches credential-dumping command lines; it does not see
#     raw LSASS handle opens.
#   * BackdoorsIn infers inbound direction from the port pattern (service port
#     local, ephemeral port remote); the direction enumerations are not used.
#   * PrivilegeRisks reports non-SYSTEM parents starting SYSTEM-context children,
#     with the raw integrity-level values included for analyst review.
#   * Rootkits reports module loads of *.sys files from outside the standard
#     driver locations.
#   * SchTasks / NewServices are derived from schtasks / sc / PowerShell command
#     lines, not task or service registration events.

_HDR = "config case_sensitive = false\n| dataset = xdr_data\n"

_PROC = "| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START\n"
_NET  = "| filter event_type = ENUM.NETWORK\n"
_DNS  = "| filter dns_query_name != null\n"

_SYSTEM_USERS = r"(?i)^(nt authority|window manager|font driver host|nt service)\\\\"
_PRIVATE_IP   = r"^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.|::1|fe80)"

QUERIES = [

    # ── LVL1  Cloud Storage ───────────────────────────────────────────────────
    (
        "CloudUsers.csv", "LVL1",
        "Cloud storage sync client outbound connections by user",
        _HDR + _NET + r"""| filter actor_process_image_path ~= "(?i)dropbox|boxsync|boxdrive|googledrive|backupandsync|icloud|pcloud|megasync|tresorit|egnyte|syncapp"
| filter actor_process_image_path !~= "(?i)microsoft|windows"
| filter action_remote_ip !~= """ + '"' + _PRIVATE_IP + '"' + r"""
| comp count() as lookups by actor_process_image_name, actor_effective_username
| sort desc lookups""",
    ),
    (
        "CloudSync.csv", "LVL1",
        "Command-line cloud upload activity (process command-line references)",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "(?i)box\\.com|dropbox\\.com|drive\\.google\\.com|mega\\.nz|wetransfer\\.com|pcloud\\.com|egnyte\\.com|mediafire\\.com|gofile\\.io|transfer\\.sh|pastebin\\.com|rclone|curl\\s+-[TFd]|-Method\\s+P(UT|OST)|Invoke-WebRequest|aws\\s+s3|gsutil|azcopy"
| filter action_process_image_name !~= "(?i)chrome|msedge|firefox"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL1  AI Users ────────────────────────────────────────────────────────
    (
        "AIUsers.csv", "LVL1",
        "AI tool desktop application usage by user (process launches)",
        _HDR + _PROC + r"""| filter action_process_image_name ~= "(?i)claude|perplexity|notion|cursor|ollama|lmstudio|gpt4all|koboldcpp|llama|whisper|krisp|otter|fathom|fireflies|elevenlabs|runway|grammarly|jasper|codeium|tabnine|windsurf|gemini|chatgpt|copilot|zed"
| filter action_process_image_name !~= "(?i)update|updater|setup|install|uninstall|helper|native-host|crash|proxy|autostarter"
| comp count() as launches by action_process_image_name, action_process_username
| sort desc launches""",
    ),
    (
        "AIWebUse.csv", "LVL1",
        "AI service browser access by DNS resolution",
        _HDR + _DNS + r"""| filter dns_query_name ~= "(?i)claude|anthropic|openai|chatgpt|perplexity|gemini|copilot\\.microsoft|grok\\.x|mistral|huggingface|character\\.ai|poe\\.com|pi\\.ai|together\\.ai|replicate\\.com|jasper\\.ai|copy\\.ai|writesonic\\.com|grammarly\\.com|notion\\.so|cursor\\.sh"
| filter actor_process_image_name !~= "(?i)MsMpEng|cyserver|cortex|svchost"
| comp count() as total_lookups, count_distinct(actor_effective_username) as unique_users by dns_query_name
| sort desc unique_users""",
    ),

    # ── LVL1  USB ─────────────────────────────────────────────────────────────
    (
        "USBConnected.csv", "LVL1",
        "USB storage device registry connection events",
        _HDR + r"""| filter event_type = ENUM.REGISTRY
| filter action_registry_key_name ~= "(?i)USBSTOR.*Disk"
| fields agent_hostname, _time, action_registry_value_name, action_registry_key_name
| sort asc agent_hostname""",
    ),
    (
        "USBUse.csv", "LVL1",
        "Process activity referencing non-standard (removable) drive letters",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "(?i)(^|[^a-z])[d-z]:\\\\"
| filter action_process_image_command_line !~= "(?i)HostGUID|HKLM:|HTTP"
| filter action_process_image_name !~= "(?i)edge|chrome"
| fields agent_hostname, _time, action_process_image_name, actor_process_command_line, action_process_image_command_line
| sort asc agent_hostname""",
    ),

    # ── LVL2  User Profile Propagation ───────────────────────────────────────
    (
        "UPPCount.csv", "LVL2",
        "User profile propagation summary — users active on multiple endpoints (process-start activity)",
        _HDR + _PROC + r"""| filter actor_effective_username != null
| filter actor_effective_username !~= """ + '"' + _SYSTEM_USERS + '"' + r"""
| comp count() as process_starts by actor_effective_username, agent_hostname
| comp count() as unique_computers, sum(process_starts) as total_activity by actor_effective_username
| filter unique_computers > 1 and unique_computers < 42
| sort desc unique_computers""",
    ),
    (
        "UPPActivity.csv", "LVL2",
        "Detailed activity for administratively flagged accounts (process-start activity)",
        _HDR + _PROC + r"""| filter actor_effective_username ~= "(?i)(^|\\\\)(administrator|admin)$"
| comp count() as process_starts, min(_time) as first_seen, max(_time) as last_seen by actor_effective_username, agent_hostname
| sort asc actor_effective_username""",
    ),

    # ── LVL2  User Services ───────────────────────────────────────────────────
    (
        "UserServices.csv", "LVL2",
        "User-space processes making outbound network connections",
        _HDR + _NET + r"""| filter actor_process_image_path ~= "(?i)\\\\users\\\\"
| filter actor_process_image_path !~= "(?i)microsoft|zoom|gotomeeting|grammarly|notion|creative"
| fields agent_hostname, _time, actor_process_image_name, actor_process_image_path, action_local_ip, action_remote_ip, action_remote_port, actor_effective_username
| sort asc agent_hostname""",
    ),

    # ── LVL2  Credential Theft ────────────────────────────────────────────────
    (
        "CredentialTheft.csv", "LVL2",
        "Credential-dumping command lines (LSASS / SAM / NTDS access indicators)",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "(?i)mimikatz|sekurlsa|lsass|minidump|comsvcs\\.dll|ntdsutil|ntds\\.dit|reg(\\.exe)?\\s+save\\s+\\S*(sam|security|system)"
| filter action_process_image_name !~= "(?i)MsMpEng|cyserver|cortex|tphkload|MBAMService|AdobeARM|Taskmgr|msiexec|MRT"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_command_line
| sort asc agent_hostname""",
    ),

    # ── LVL2  WMI Lateral Movement ───────────────────────────────────────────
    (
        "WMILateral.csv", "LVL2",
        "WMI-spawned process creation (lateral movement indicator)",
        _HDR + _PROC + r"""| filter actor_process_image_name ~= "(?i)wmiprvse"
| filter action_process_image_name !~= "(?i)wmiprvse|werfault"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL2  Local Privilege Escalation ──────────────────────────────────────
    (
        "LPE.csv", "LVL2",
        "Local privilege escalation — non-system user spawning admin tools",
        _HDR + _PROC + r"""| filter actor_effective_username != null
| filter actor_effective_username !~= """ + '"' + _SYSTEM_USERS + '"' + r"""
| filter action_process_image_name ~= "(?i)^(cmd|powershell|net|net1|whoami|runas)\\.exe$"
| filter action_process_image_command_line !~= "(?i)cortex|cyserver"
| comp count() as event_count by agent_hostname, actor_effective_username, action_process_image_name, action_process_image_command_line
| sort desc event_count""",
    ),

    # ── LVL2  Privilege Hygiene ───────────────────────────────────────────────
    (
        "PrivilegeRisks.csv", "LVL2",
        "Privilege hygiene — non-SYSTEM parents starting SYSTEM-context processes (integrity levels included raw)",
        _HDR + _PROC + r"""| filter actor_effective_username != null and action_process_username ~= "(?i)^nt authority\\\\system$"
| filter actor_effective_username !~= """ + '"' + _SYSTEM_USERS + '"' + r"""
| filter actor_process_image_name !~= "(?i)^(msiexec|setup|install|installer|TrustedInstaller)"
| comp count() as event_count by agent_hostname, actor_process_image_name, actor_effective_username, actor_process_integrity_level, action_process_image_name, action_process_integrity_level, action_process_image_path, action_process_image_command_line
| sort desc event_count""",
    ),

    # ── LVL3  Network Tunnels ─────────────────────────────────────────────────
    (
        "NetworkTunnels.csv", "LVL3",
        "Tunnel tool process network connections (ngrok, cloudflared, frpc, etc.)",
        _HDR + _NET + r"""| filter actor_process_image_path ~= "(?i)ngrok|cloudflared|frpc|ligolo|chisel|rathole|tunnelto|[\\\\/]tor(\\.exe)?$|tor browser"
| filter actor_process_image_path !~= "(?i)monitor|doctor|repository|protector|collector|editor|windowsapps|laborator|microsoft|torun|driverstore"
| fields agent_hostname, _time, actor_process_image_name, actor_process_image_path, action_local_ip, action_remote_ip, action_remote_port, actor_effective_username
| sort asc agent_hostname""",
    ),

    # ── LVL3  DNS / DGA ───────────────────────────────────────────────────────
    (
        "DGABeacons.csv", "LVL3",
        "High-frequency NXDOMAIN DNS requests (DGA / beaconing pattern, >100 hits)",
        _HDR + _DNS + r"""| filter dns_reply_code ~= "(?i)nxdomain|^3$"
| filter dns_query_name !~= "(?i)rocketcyber|digicert|grammarly|opendns|typekit|in-addr\\.arpa|microsoft|wpad|_ldap|office|amazon|google|yahoo|azure|verizon|kaseya|adobe|example|dynatrace|webex|\\.pub\\.|cdn|arpa|windowsupdate|doubleclick|zoom|pki|msft|metrix|trafficmanager|kerberos|tcp\\.|duckduckgo|southwest|ipv4|ipv6|autodiscover|actionablemessage|claude|scorecard|casalmedia|verisign|paloaltonetworks|traps"
| comp count() as nxdomain_count by agent_hostname, actor_process_image_name, actor_effective_username, dns_query_name
| filter nxdomain_count > 100
| sort desc nxdomain_count""",
    ),
    (
        "BadTLDs.csv", "LVL3",
        "DNS queries to high-risk country-code and generic TLDs",
        _HDR + _DNS + r"""| filter dns_query_name ~= "(?i)\\.(ru|cn|onion|tk|xyz|top|icu)\\.?$"
| filter actor_process_image_name !~= "(?i)MsMpEng|cyserver|cortex"
| filter dns_query_name !~= "(?i)rubicon|digicert"
| fields agent_hostname, actor_process_image_name, dns_query_name, actor_effective_username, _time
| sort asc agent_hostname""",
    ),

    # ── LVL3  Backdoors ───────────────────────────────────────────────────────
    (
        "BackdoorsIn.csv", "LVL3",
        "Inbound connections on non-standard ports (direction inferred: service port local, ephemeral port remote)",
        _HDR + _NET + r"""| filter action_local_port < 10000 and action_remote_port >= 10000
| filter action_remote_ip != "127.0.0.1" and action_remote_ip != "::1"
| filter action_local_port != 135 and action_local_port != 139 and action_local_port != 0 and action_local_port != 7680
| fields agent_hostname, actor_process_image_name, actor_process_image_path, action_local_ip, action_local_port, action_remote_ip, action_remote_port, actor_effective_username, _time
| sort asc agent_hostname""",
    ),
    (
        "BackdoorsOut.csv", "LVL3",
        "Outbound connections on non-standard ports and protocols",
        _HDR + _NET + r"""| filter action_remote_ip !~= """ + '"' + _PRIVATE_IP + '"' + r"""
| filter action_remote_port not in (53, 80, 8080, 8081, 443, 3268, 3478, 5228, 7680, 19305, 52311)
| filter actor_process_image_name !~= "(?i)cyserver|cortex|MsMpEng|AgentMon|KaseyaEndpoint|ntoskrnl|OUTLOOK|KDService|ms-teams"
| filter actor_process_command_line !~= "(?i)update|mojo|office|rocket"
| fields agent_hostname, _time, action_local_ip, action_local_port, action_remote_ip, action_remote_port, actor_process_image_name, actor_process_image_path, actor_process_command_line, actor_effective_username
| sort asc agent_hostname""",
    ),

    # ── LVL3  Beacons ─────────────────────────────────────────────────────────
    (
        "Beacons.csv", "LVL3",
        "High-frequency outbound IP connections (>500) by process/destination",
        _HDR + _NET + r"""| filter action_remote_ip !~= """ + '"' + _PRIVATE_IP + '"' + r"""
| filter actor_process_image_name !~= "(?i)MsMpEng|cyserver|cortex|proxy|MpsMonitor|spoolsv|MsSense|Rocket|Spotify|edge|opera|firefox|chrome|adobe"
| filter actor_process_command_line !~= "(?i)office|Onedrive|Zoom|Program Files|ProgramData|Kaseya|instal|upgr|update|claude"
| comp count() as connection_count by agent_hostname, actor_process_image_name, action_remote_ip
| filter connection_count > 500
| sort desc connection_count""",
    ),

    # ── LVL4  RMM ─────────────────────────────────────────────────────────────
    (
        "RmmUse.csv", "LVL4",
        "RMM tool process creation events",
        _HDR + _PROC + r"""| filter action_process_image_path ~= "(?i)mstsc|TeamViewer|GoToMeeting|g2m|AnyDesk|ScreenConnect|ConnectWise|LogMeIn|Splashtop|Bomgar|BeyondTrust|NinjaRMM|Atera|Pulseway|remoting_host|VNC|ZohoAssist|Supremo|Datto|DameWare|DWRCS|dwrcc"
| filter action_process_image_path !~= "(?i)driverstore"
| fields agent_hostname, _time, action_process_image_name, action_process_image_path, action_process_username
| sort asc agent_hostname""",
    ),
    (
        "RMMComms.csv", "LVL4",
        "RMM tool active network connections",
        _HDR + _NET + r"""| filter actor_process_image_path ~= "(?i)mstsc|TSClient|TeamViewer|AnyDesk|ScreenConnect|ConnectWise|LogMeIn|Splashtop|Bomgar|BeyondTrust|NinjaRMM|RealVNC|TightVNC|UltraVNC|WinVNC|vncviewer|Datto|Zoho|Supremo|Rescue|GoToAssist|GoToMyPC|GoTo|Citrix|ISL|RemotePC|Getscreen|Fixme|Mikogo|BASup|RustDesk|LMI_Rescue|LanDesk|DameWare|DWRCS|dwrcc"
| fields agent_hostname, _time, actor_process_image_name, actor_process_image_path, action_local_ip, action_remote_ip, action_remote_port, actor_effective_username
| sort asc agent_hostname""",
    ),

    # ── LVL4  LOLBin ─────────────────────────────────────────────────────────
    (
        "LolBinUse.csv", "LVL4",
        "Living-off-the-land binary execution",
        _HDR + _PROC + r"""| filter action_process_image_name ~= "(?i)^(certutil|bitsadmin|mshta|sfc|hh|wscript|cscript|regsvr32|rundll32|msiexec|wmic|installutil|regasm|regsvcs|cmstp|msbuild|dnscmd|odbcconf|pcalua|pwsh|powershell|desktopimgdownldr|esentutl|extrac32|findstr|makecab|mavinject|msdeploy|msdt|presentationhost|replace|rpcping|wab|xwizard)(\\.exe)?$"
| filter action_process_image_command_line !~= "(?i)Embedding|CbsPersist|Kaseya|REPAIRFROMAPP|PfSvWsSwap"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_path, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),
    (
        "LolBinMasq.csv", "LVL4",
        "Potential LOLBin masquerade — system binary names running from non-standard paths",
        _HDR + _PROC + r"""| filter action_process_image_name ~= "(?i)^(svhost|svchost|rundll|rundll32|service|cmd)\\.exe$"
| filter action_process_image_path !~= "(?i)system32|syswow64|winsxs"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_path, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL4  Base64 ──────────────────────────────────────────────────────────
    (
        "Base64Activities.csv", "LVL4",
        "Encoded command execution (base64 == padding in command line)",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "[A-Za-z0-9+/]{16,}=="
| filter action_process_image_name !~= "(?i)edge|chrome"
| fields agent_hostname, _time, action_process_image_name, actor_process_command_line, action_process_image_command_line
| sort asc agent_hostname""",
    ),

    # ── LVL4  Scheduled Tasks ─────────────────────────────────────────────────
    (
        "SchTasks.csv", "LVL4",
        "Scheduled task creation referencing user or temp paths",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "(?i)schtasks.*/create|register-scheduledtask"
| filter action_process_image_command_line ~= "(?i)\\\\users\\\\|\\\\temp\\\\|appdata"
| filter action_process_image_command_line !~= "(?i)OneDrive|Lvf|zoom|piriform|office|edge"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL4  Process Injection ───────────────────────────────────────────────
    (
        "ProcessInjections.csv", "LVL4",
        "Injection events — remote thread / memory injection into another process",
        _HDR + r"""| filter event_type = ENUM.INJECTION
| filter action_remote_process_image_name != null
| alter same_process = if(actor_process_image_name = action_remote_process_image_name, 1, 0)
| filter same_process = 0
| filter actor_process_image_name !~= "(?i)WerFault|WerFaultSecure|MBAM|MsMpEng|cyserver|cortex|csrss|wininit|services\\.exe"
| filter action_remote_process_image_name !~= "(?i)spoolsv"
| fields agent_hostname, _time, actor_process_image_name, actor_process_image_path, action_remote_process_image_name, actor_effective_username, actor_process_command_line
| sort asc agent_hostname""",
    ),

    # ── LVL4  Office Shells ───────────────────────────────────────────────────
    (
        "ShellsSpawn.csv", "LVL4",
        "Office applications spawning shells or LOLBins",
        _HDR + _PROC + r"""| filter actor_process_image_name ~= "(?i)winword|excel|powerpnt|outlook|onenote|msaccess|mspub"
| filter action_process_image_name ~= "(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|ftp|curl|nslookup|wmic|msbuild|installutil|regasm|regsvcs|cmstp|odbcconf|schtasks|at|sc|msiexec|reg|regedit|net|net1|nltest|whoami|systeminfo|ipconfig|tasklist|taskkill|vssadmin|wbadmin|bcdedit|esentutl|expand|extrac32|findstr|hh|makecab|mavinject|msdt|pcalua|presentationhost|xwizard|replace|forfiles|mmc|explorer|ping|arp|netstat|icacls|takeown|attrib|cipher|sdelete|dnscmd|rpcping)(\\.exe)?$"
| filter action_process_image_name !~= "(?i)acrobat|cabinet"
| filter action_process_image_command_line !~= "(?i)Office|OfficeC2R|Teams"
| fields agent_hostname, _time, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line, actor_process_command_line
| sort asc agent_hostname""",
    ),

    # ── LVL4  User Executables ────────────────────────────────────────────────
    (
        "UserExecs.csv", "LVL4",
        "Executables dropped in writable user locations (Temp, AppData, Downloads)",
        _HDR + r"""| filter event_type = ENUM.FILE
| filter action_file_path ~= "(?i)\\\\temp\\\\|\\\\appdata\\\\roaming\\\\|\\\\downloads\\\\|\\\\public\\\\"
| filter action_file_name ~= "(?i)\\.(exe|cmd|ps1|vbs|scr|jar)$"
| filter actor_process_image_name != null
| filter actor_process_image_name !~= "(?i)MsMpEng|cyserver|cortex|msiexec|WindowsInstaller"
| filter action_file_path !~= "(?i)Program Files|chrom|ProgramData"
| filter actor_process_image_name !~= "(?i)setup|updat|inst|vc_redist|^HP|icarus|package|MSI|runtime|claude|creative|driver|zoom"
| fields agent_hostname, _time, actor_effective_username, actor_process_image_name, action_file_name, action_file_path
| sort asc agent_hostname""",
    ),

    # ── LVL4  New Services ────────────────────────────────────────────────────
    (
        "NewServices.csv", "LVL4",
        "Windows service creation or reconfiguration via sc.exe / New-Service",
        _HDR + _PROC + r"""| filter (action_process_image_name ~= "(?i)^sc(\\.exe)?$" and action_process_image_command_line ~= "(?i)\\b(create|config)\\b") or action_process_image_command_line ~= "(?i)new-service"
| filter actor_process_image_name !~= "(?i)msiexec|TrustedInstaller|AgentMon|Lenovo"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL4  Rootkits / Driver Loads ────────────────────────────────────────
    (
        "Rootkits.csv", "LVL4",
        "Kernel driver (.sys) loads from outside standard driver locations (rootkit indicator)",
        _HDR + r"""| filter event_type = ENUM.LOAD_IMAGE
| filter action_module_path ~= "(?i)\\.sys$"
| filter action_module_path !~= "(?i)\\\\windows\\\\system32\\\\(drivers|driverstore)|\\\\windows\\\\winsxs"
| fields agent_hostname, _time, actor_process_image_name, action_module_path, action_module_sha256
| sort asc agent_hostname""",
    ),

    # ── LVL4  Suspicious Scripts ──────────────────────────────────────────────
    (
        "SuspScripts.csv", "LVL4",
        "Process command lines with download or reflective-load indicators",
        _HDR + _PROC + r"""| filter action_process_image_command_line ~= "IEX|Invoke-Expression|Net\\.WebClient|DownloadString|DownloadFile|WebRequest|bitsadmin|Start-BitsTransfer|Reflection\\.Assembly|FromBase64String"
| fields agent_hostname, _time, actor_process_image_name, action_process_image_name, action_process_image_command_line, actor_process_command_line, action_process_username
| sort asc agent_hostname""",
    ),

    # ── LVL5  OS Builds ───────────────────────────────────────────────────────
    (
        "OSBuilds.csv", "LVL5",
        "Endpoint OS type and version inventory (from endpoint telemetry)",
        _HDR + r"""| filter agent_os_sub_type != null
| comp count() as events by agent_hostname, agent_os_type, agent_os_sub_type
| fields agent_hostname, agent_os_type, agent_os_sub_type
| sort asc agent_hostname""",
    ),

    # ── LVL5  Endpoint Activity Health ───────────────────────────────────────
    (
        "Endpoints.csv", "LVL5",
        "Daily event counts per endpoint (process, network, registry) for health comparison",
        _HDR + r"""| filter event_type in (ENUM.PROCESS, ENUM.NETWORK, ENUM.REGISTRY)
| bin _time span = 1d
| comp count() as event_count by _time, agent_hostname, event_type
| sort asc _time""",
    ),

    # ── Manual / Entra ID exports ─────────────────────────────────────────────
    # No Cortex XDR API equivalent; must be sourced from the Entra portal.
    ("EntraUsers.csv",  "LVL2", "Entra ID user accounts (Entra portal export — manual)", None),
    ("EntraGroups.csv", "LVL2", "Entra ID group memberships (Entra portal export — manual)", None),
    ("EntraRoles.csv",  "LVL2", "Entra ID privileged role assignments (Entra portal export — manual)", None),
]

# Application inventory is collected through XQL (preset, not xdr_data).
APP_INVENTORY_XQL = f"preset = {INVENTORY_PRESET}\n| limit 1000000"


# ── Cortex XDR API client ─────────────────────────────────────────────────────

def normalise_base_url(fqdn: str) -> str:
    """Turn a tenant FQDN into the API base URL (https://api-<fqdn>)."""
    value = fqdn.strip().rstrip("/")
    if value.lower().startswith(("http://", "https://")):
        return value
    if value.lower().startswith("api-"):
        return f"https://{value}"
    return f"https://api-{value}"


class XDRClient:
    """
    Thin Cortex XDR REST client.  Every call is a POST with a JSON
    {"request_data": {...}} envelope.  Supports Standard and Advanced API keys.
    Retries HTTP 429 and 5xx with exponential back-off.
    """

    def __init__(self, base_url: str, api_key: str, api_key_id: str,
                 auth_type: str = "standard"):
        self.base       = base_url.rstrip("/")
        self.api_key    = api_key
        self.api_key_id = api_key_id
        self.auth_type  = auth_type
        self.session    = requests.Session()
        self.last_quota: float | None = None     # remaining_quota from the latest XQL result

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _auth_headers(self) -> dict:
        headers = {
            "x-xdr-auth-id": str(self.api_key_id),
            "Content-Type":  "application/json",
        }
        if self.auth_type == "advanced":
            # Advanced keys: a fresh nonce + timestamp on EVERY request;
            # Authorization is the SHA-256 of key + nonce + timestamp.
            nonce = "".join(secrets.choice(string.ascii_letters + string.digits)
                            for _ in range(64))
            ts = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
            headers["x-xdr-nonce"]     = nonce
            headers["x-xdr-timestamp"] = ts
            headers["Authorization"]   = hashlib.sha256(
                f"{self.api_key}{nonce}{ts}".encode("utf-8")).hexdigest()
        else:
            headers["Authorization"] = self.api_key
        return headers

    # ── Transport ─────────────────────────────────────────────────────────────

    def post(self, path: str, request_data: dict, extra_headers: dict | None = None,
             stream: bool = False) -> requests.Response:
        url = f"{self.base}{API_PREFIX}{path}"
        for attempt in range(MAX_RETRIES + 1):
            headers = self._auth_headers()          # re-sign each attempt
            if extra_headers:
                headers.update(extra_headers)
            r = self.session.post(url, headers=headers,
                                  json={"request_data": request_data},
                                  timeout=HTTP_TIMEOUT, stream=stream)
            if r.status_code == 429 or r.status_code >= 500:
                if attempt < MAX_RETRIES:
                    wait = float(r.headers.get("Retry-After") or 2 ** (attempt + 1))
                    log.warning("    HTTP %d from %s — retrying in %.0fs (%d/%d)",
                                r.status_code, path, wait, attempt + 1, MAX_RETRIES)
                    time.sleep(wait)
                    continue
            r.raise_for_status()
            return r
        raise RuntimeError("unreachable")           # pragma: no cover

    # ── XQL ───────────────────────────────────────────────────────────────────

    def xql_start(self, query: str, from_ms: int, to_ms: int) -> str:
        """Submit an XQL query; returns the execution ID."""
        body = {"query": query, "timeframe": {"from": from_ms, "to": to_ms}}
        reply = self.post("/xql/start_xql_query", body).json().get("reply")
        query_id = reply if isinstance(reply, str) else (reply or {}).get("execution_id")
        if not query_id:
            raise RuntimeError(f"start_xql_query returned no execution ID: {reply!r}")
        return query_id

    def xql_results(self, query_id: str) -> dict:
        """One poll of get_query_results; returns the 'reply' object."""
        body = {"query_id": query_id, "pending_flag": True, "format": "json"}
        reply = self.post("/xql/get_query_results", body).json().get("reply") or {}
        if "remaining_quota" in reply:
            self.last_quota = reply["remaining_quota"]
        return reply

    def xql_stream(self, stream_id: str) -> list[dict]:
        """Fetch a result set larger than the 1,000-row inline cap."""
        r = self.post("/xql/get_query_results_stream",
                      {"stream_id": stream_id, "is_gzip_compressed": False})
        return parse_stream_body(r.text)

    # ── Endpoint inventory ────────────────────────────────────────────────────

    def fetch_all_endpoints(self) -> list[dict]:
        """Page through POST /endpoints/get_endpoint, 100 per call."""
        rows: list[dict] = []
        start = 0
        while True:
            reply = self.post("/endpoints/get_endpoint", {
                "search_from": start,
                "search_to":   start + PAGE_SIZE,
                "sort":        {"field": "first_seen", "keyword": "asc"},
            }).json().get("reply") or {}
            batch = reply.get("endpoints") or []
            rows.extend(batch)
            total = reply.get("total_count") or len(rows)
            log.info("    fetched %d / %d endpoints …", len(rows), total)
            start += len(batch)
            if not batch or start >= total:
                break
        return rows

    # ── Management audit log ──────────────────────────────────────────────────

    def fetch_audit_logs(self, from_ms: int, to_ms: int) -> list[dict]:
        """Page through POST /audits/management_logs for the window, 100 per call."""
        rows: list[dict] = []
        start = 0
        filters = [
            {"field": "timestamp", "operator": "gte", "value": from_ms},
            {"field": "timestamp", "operator": "lte", "value": to_ms},
        ]
        while True:
            reply = self.post("/audits/management_logs", {
                "filters":     filters,
                "search_from": start,
                "search_to":   start + PAGE_SIZE,
            }).json().get("reply") or {}
            batch = reply.get("data") or []
            rows.extend(batch)
            total = reply.get("total_count") or len(rows)
            log.info("    fetched %d / %d audit records …", len(rows), total)
            start += len(batch)
            if not batch or start >= total:
                break
        # Oldest first so the CSV reads chronologically
        rows.sort(key=lambda r: r.get("AUDIT_INSERT_TIME") or 0)
        return rows


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iso_to_epoch_ms(iso: str) -> int:
    """Convert ISO-8601 UTC string to Unix epoch milliseconds."""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stream_body(text: str) -> list[dict]:
    """
    Parse a get_query_results_stream body.  The stream is documented only as a
    chunked response; accept newline-delimited JSON objects or a single JSON array.
    """
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _cell(value):
    """Make a value CSV-friendly: scalars as-is, lists of scalars joined, the rest as JSON."""
    if isinstance(value, (dict, list)):
        if isinstance(value, list) and all(not isinstance(v, (dict, list)) for v in value):
            return "; ".join(str(v) for v in value)
        return json.dumps(value, default=str)
    return value


def records_to_csv(records: list[dict], path: Path) -> int:
    """Write a list of dicts to CSV (nested values flattened); returns row count."""
    if not records:
        path.write_text("", encoding="utf-8")
        return 0
    all_keys: list[str] = []
    seen: set[str] = set()
    for rec in records:
        for k in rec.keys():
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow({k: _cell(v) for k, v in rec.items()})
    return len(records)


def make_coc_entry(csv_name: str, level: str, description: str, query_type: str,
                   from_date: str | None = None, to_date: str | None = None) -> dict:
    return {
        "file":         csv_name,
        "level":        level,
        "description":  description,
        "query_type":   query_type,
        "from_date":    from_date,
        "to_date":      to_date,
        "status":       None,
        "row_count":    None,
        "sha256":       None,
        "collected_at": None,
        "note":         None,
    }


def finalise_entry(entry: dict, path: Path, row_count: int) -> None:
    entry["status"]       = "success"
    entry["row_count"]    = row_count
    entry["sha256"]       = sha256_file(path)
    entry["collected_at"] = iso_now()


def run_xql(client: XDRClient, query: str, from_ms: int, to_ms: int,
            entry: dict) -> list[dict] | None:
    """
    Run one XQL query to completion and return its rows, or None on failure
    (entry['status'] / entry['note'] are set).  Records execution ID, query cost,
    remaining quota and a hash of the query text in the CoC entry.
    """
    entry["query_sha256"] = sha256_text(query)
    query_id = client.xql_start(query, from_ms, to_ms)
    entry["query_id"] = query_id
    log.info("    executionId: %s", query_id)

    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        reply  = client.xql_results(query_id)
        status = reply.get("status", "UNKNOWN")
        log.info("    status: %-16s results: %s", status, reply.get("number_of_results", "-"))

        if status in ("SUCCESS", "PARTIAL_SUCCESS"):
            entry["query_cost"]      = reply.get("query_cost")
            entry["remaining_quota"] = reply.get("remaining_quota")
            if status == "PARTIAL_SUCCESS":
                entry["note"] = "Cortex reported PARTIAL_SUCCESS — result set may be incomplete."
                log.warning("    PARTIAL_SUCCESS — results may be incomplete")
            results = reply.get("results") or {}
            stream_id = results.get("stream_id")
            if stream_id:
                log.info("    large result set — streaming (stream_id %s)", stream_id)
                return client.xql_stream(stream_id)
            return results.get("data") or []

        if status in ("FAIL", "FAILED", "ERROR"):
            entry["status"] = "query_failed"
            entry["note"]   = f"XQL query ended with status {status}: {json.dumps(reply, default=str)[:500]}"
            log.error("    query ended with status: %s", status)
            return None
        time.sleep(POLL_INTERVAL)

    entry["status"] = "query_failed"
    entry["note"]   = f"Timed out after {POLL_TIMEOUT}s waiting for XQL query {query_id}."
    log.error("    timed out after %ds", POLL_TIMEOUT)
    return None


def guarded(entry: dict, hint: str = ""):
    """Decorator-free helper: run a collection step, recording errors in the CoC entry."""
    class _Guard:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc is None:
                return False
            if isinstance(exc, requests.HTTPError):
                entry["status"] = "http_error"
                entry["note"]   = f"{exc}  {hint}".strip()
                log.error("    HTTP error: %s", exc)
            else:
                entry["status"] = "error"
                entry["note"]   = str(exc)
                log.error("    Unexpected error: %s", exc)
            return True        # swallow; the CoC entry carries the failure
    return _Guard()


# ── Management API / inventory collectors ─────────────────────────────────────

def collect_host_inventory(client: XDRClient, output_dir: Path, coc: list[dict]) -> None:
    csv_name = "HostInventory.csv"
    out_path = output_dir / csv_name
    entry = make_coc_entry(
        csv_name, "LVL5",
        "Full endpoint inventory — OS, agent version, status, last seen, isolation, "
        "policy, group (POST /public_api/v1/endpoints/get_endpoint)",
        "management_api",
    )
    log.info("[LVL5] %s  (management API — endpoint inventory)", csv_name)
    with guarded(entry):
        rows = client.fetch_all_endpoints()
        finalise_entry(entry, out_path, records_to_csv(rows, out_path))
        log.info("    wrote %d rows → %s  [sha256: %s…]",
                 entry["row_count"], out_path.name, entry["sha256"][:16])
    coc.append(entry)


def collect_app_inventory(client: XDRClient, output_dir: Path, coc: list[dict]) -> None:
    csv_name = "app-inventory.csv"
    out_path = output_dir / csv_name
    entry = make_coc_entry(
        csv_name, "LVL5",
        f"Application inventory across all endpoints via XQL preset {INVENTORY_PRESET} "
        "(requires Cortex XDR Host Insights add-on)",
        "xql_inventory",
    )
    log.info("[LVL5] %s  (XQL — %s)", csv_name, INVENTORY_PRESET)
    now_ms = int(time.time() * 1000)
    with guarded(entry, hint="(application inventory requires the Host Insights add-on)"):
        # Inventory is a current-state snapshot; the timeframe is a formality.
        rows = run_xql(client, APP_INVENTORY_XQL, now_ms - 86_400_000, now_ms, entry)
        if rows is not None:
            finalise_entry(entry, out_path, records_to_csv(rows, out_path))
            log.info("    wrote %d rows → %s  [sha256: %s…]",
                     entry["row_count"], out_path.name, entry["sha256"][:16])
    if entry["status"] == "query_failed":
        entry["note"] = (entry["note"] or "") + \
            "  Application inventory requires the Host Insights add-on; " \
            "export Host Inventory → Applications from the console if it is not licensed."
    coc.append(entry)


def collect_mgmt_activity(client: XDRClient, output_dir: Path, coc: list[dict],
                          from_ms: int, to_ms: int, from_date: str, to_date: str) -> None:
    csv_name = "MgmtActivity.csv"
    out_path = output_dir / csv_name
    entry = make_coc_entry(
        csv_name, "LVL2",
        "Management console audit log — admin logins, policy changes, agent actions, "
        "role and API-key changes (POST /public_api/v1/audits/management_logs)",
        "management_api", from_date, to_date,
    )
    log.info("[LVL2] %s  (management API — audit log)", csv_name)
    with guarded(entry, hint="(verify the API key's role allows reading audit logs)"):
        rows = client.fetch_audit_logs(from_ms, to_ms)
        finalise_entry(entry, out_path, records_to_csv(rows, out_path))
        log.info("    wrote %d rows → %s  [sha256: %s…]",
                 entry["row_count"], out_path.name, entry["sha256"][:16])
    coc.append(entry)


# ── Main runner ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> None:
    if args.from_date and args.to_date:
        from_date = args.from_date
        to_date   = args.to_date
    else:
        now       = datetime.now(timezone.utc)
        to_date   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        from_date = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    from_ms = iso_to_epoch_ms(from_date)
    to_ms   = iso_to_epoch_ms(to_date)

    only = {n.strip().lower() for n in args.only.split(",")} if args.only else None

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_url = normalise_base_url(args.fqdn)
    client   = XDRClient(base_url, args.api_key, args.api_key_id, args.auth_type)

    run_start = iso_now()
    run_host  = platform.node()
    run_user  = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    coc_entries: list[dict] = []

    script_path = Path(__file__).resolve()
    script_hash = sha256_file(script_path) if script_path.exists() else "unavailable"

    log.info("=" * 70)
    log.info("Cortex XDR Cyber Risk Assessment Collection Script")
    log.info("  Range  : %s → %s", from_date, to_date)
    log.info("  Tenant : %s  (%s key)", base_url, args.auth_type)
    log.info("  Output : %s", output_dir.resolve())
    log.info("  Script : %s  [sha256: %s]", script_path.name, script_hash[:16] + "…")
    if only:
        log.info("  Subset : %s", ", ".join(sorted(only)))
    log.info("=" * 70)

    def selected(name: str) -> bool:
        return only is None or name.lower() in only

    # ── Phases 1–3: management API / inventory ────────────────────────────────
    if selected("HostInventory.csv"):
        log.info("")
        log.info("── Phase 1: Endpoint inventory (management API) ──────────────────")
        collect_host_inventory(client, output_dir, coc_entries)

    if selected("app-inventory.csv"):
        log.info("")
        log.info("── Phase 2: Application inventory (XQL host inventory) ───────────")
        collect_app_inventory(client, output_dir, coc_entries)

    if selected("MgmtActivity.csv"):
        log.info("")
        log.info("── Phase 3: Management audit log (management API) ────────────────")
        collect_mgmt_activity(client, output_dir, coc_entries,
                              from_ms, to_ms, from_date, to_date)

    # ── Phase 4: XQL queries ──────────────────────────────────────────────────
    xql_count = sum(1 for n, _, _, q in QUERIES if q is not None and selected(n))
    log.info("")
    log.info("── Phase 4: XQL queries (%d total) ────────────────────────────────", xql_count)

    for csv_name, level, description, query in QUERIES:
        if not selected(csv_name):
            continue
        out_path = output_dir / csv_name
        entry = make_coc_entry(
            csv_name, level, description,
            "xql_api" if query else "manual_export",
            from_date if query else None,
            to_date   if query else None,
        )

        if query is None:
            if out_path.exists():
                entry["sha256"]       = sha256_file(out_path)
                entry["status"]       = "manually_provided"
                entry["collected_at"] = iso_now()
                with out_path.open(encoding="utf-8", errors="replace") as f:
                    entry["row_count"] = max(0, sum(1 for _ in f) - 1)
                log.info("[%s] %s — manual export found, hashed (%d rows)",
                         level, csv_name, entry["row_count"])
            else:
                entry["status"] = "pending_manual_export"
                entry["note"]   = ("Export manually from the Microsoft Entra portal "
                                   "and place in the output directory before analysis.")
                log.warning("[%s] %s — NOT FOUND (manual export required)", level, csv_name)
            coc_entries.append(entry)
            continue

        log.info("[%s] %s", level, csv_name)
        with guarded(entry, hint="(check XQL syntax / dataset access / quota)"):
            rows = run_xql(client, query, from_ms, to_ms, entry)
            if rows is not None:
                finalise_entry(entry, out_path, records_to_csv(rows, out_path))
                log.info("    wrote %d rows → %s  [sha256: %s…]",
                         entry["row_count"], out_path.name, entry["sha256"][:16])
        coc_entries.append(entry)

    # ── Write chain-of-custody manifest ──────────────────────────────────────
    coc_path = output_dir / COC_FILENAME
    manifest = {
        "title":       "Chain of Custody — Cortex XDR Cyber Risk Assessment",
        "description": (
            "This manifest records every file produced or expected by the "
            "cortex_query_runner.py script, including SHA-256 hashes for integrity "
            "verification, query provenance, collection timestamps, and row counts. "
            "It should accompany the CSV files when submitted for analysis."
        ),
        "collection_metadata": {
            "script":              script_path.name,
            "script_sha256":       script_hash,
            "operator_host":       run_host,
            "operator_user":       run_user,
            "run_started_utc":     run_start,
            "run_finished_utc":    iso_now(),
            "query_from_date":     from_date,
            "query_to_date":       to_date,
            "cortex_base_url":     base_url,
            "api_key_id":          str(args.api_key_id),
            "auth_type":           args.auth_type,
            "subset":              sorted(only) if only else None,
            "xql_remaining_quota": client.last_quota,
            "python_version":      sys.version,
            "platform":            platform.platform(),
        },
        "files": coc_entries,
    }

    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    manifest_hash = sha256_file(coc_path)
    manifest["manifest_sha256"] = manifest_hash
    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    log.info("=" * 70)
    log.info("Chain of custody written → %s", coc_path)
    log.info("Manifest SHA-256: %s", manifest_hash)

    api_ok     = sum(1 for e in coc_entries if e["status"] == "success"
                     and e.get("query_type") in ("management_api", "xql_inventory"))
    xql_ok     = sum(1 for e in coc_entries if e["status"] == "success"
                     and e.get("query_type") == "xql_api")
    manual_ok  = sum(1 for e in coc_entries if e["status"] == "manually_provided")
    pending    = sum(1 for e in coc_entries if e["status"] == "pending_manual_export")
    failed     = sum(1 for e in coc_entries if e["status"] not in
                     ("success", "manually_provided", "pending_manual_export"))
    total_rows = sum(e["row_count"] or 0 for e in coc_entries)

    log.info("")
    log.info("  Management / inventory OK : %d  (HostInventory, app-inventory, MgmtActivity)", api_ok)
    log.info("  XQL queries OK            : %d", xql_ok)
    log.info("  Manual exports found      : %d", manual_ok)
    log.info("  Manual exports MISSING    : %d  (Entra ID — add before analysis)", pending)
    log.info("  Errors                    : %d", failed)
    log.info("  Total data rows           : %d", total_rows)
    if client.last_quota is not None:
        log.info("  XQL quota remaining       : %s", client.last_quota)
    log.info("=" * 70)

    if failed:
        log.warning("Collections that failed (see 'note' in %s):", COC_FILENAME)
        for e in coc_entries:
            if e["status"] not in ("success", "manually_provided", "pending_manual_export"):
                log.warning("  %-28s  %s", e["file"], e["status"])
    if pending:
        log.warning("Files requiring manual export:")
        for e in coc_entries:
            if e["status"] == "pending_manual_export":
                log.warning("  %-35s  [%s] %s", e["file"], e["level"], e["description"])


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cortex XDR bulk XQL query runner with chain-of-custody manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API key requirements:
  Role         : Instance Administrator, or a custom role permitting XQL queries,
                 endpoint read and audit-log read
  Key type     : Standard (default) or Advanced (--auth-type advanced)
  Add-on       : Host Insights, only for app-inventory.csv

Examples:
  # Last 90 days, standard key
  python cortex_query_runner.py --fqdn acme.xdr.us.paloaltonetworks.com \\
      --api-key KEY --api-key-id 12

  # Advanced key, keys from the environment, specific window
  export CORTEX_API_KEY=... CORTEX_API_KEY_ID=12
  python cortex_query_runner.py --fqdn acme.xdr.us.paloaltonetworks.com \\
      --auth-type advanced \\
      --from-date 2026-02-25T00:00:00Z --to-date 2026-05-25T23:59:59Z

  # Re-run a few outputs only (e.g. after fixing a query)
  python cortex_query_runner.py --fqdn acme.xdr.us.paloaltonetworks.com \\
      --api-key KEY --api-key-id 12 --only Beacons.csv,RmmUse.csv --days 30
""",
    )
    parser.add_argument("--fqdn", required=True,
                        help="Tenant FQDN (e.g. acme.xdr.us.paloaltonetworks.com) or full API URL")
    parser.add_argument("--api-key", dest="api_key",
                        default=os.environ.get("CORTEX_API_KEY"),
                        help="API key (or set CORTEX_API_KEY)")
    parser.add_argument("--api-key-id", dest="api_key_id",
                        default=os.environ.get("CORTEX_API_KEY_ID"),
                        help="API key ID (or set CORTEX_API_KEY_ID)")
    parser.add_argument("--auth-type", dest="auth_type", choices=("standard", "advanced"),
                        default="standard", help="API key type (default: standard)")
    parser.add_argument("--days", type=int, default=90,
                        help="Look-back window in days if --from-date/--to-date omitted (default: 90)")
    parser.add_argument("--from-date", dest="from_date", default=None,
                        help="Query start ISO-8601 UTC (e.g. 2026-02-25T00:00:00Z)")
    parser.add_argument("--to-date", dest="to_date", default=None,
                        help="Query end   ISO-8601 UTC (e.g. 2026-05-25T23:59:59Z)")
    parser.add_argument("--output", default="./cortex_assessment_output",
                        help="Output directory for CSV files and CoC manifest")
    parser.add_argument("--only", default=None,
                        help="Comma-separated output file names to collect (default: all)")

    args = parser.parse_args()

    if bool(args.from_date) ^ bool(args.to_date):
        parser.error("--from-date and --to-date must both be provided together.")
    if not args.api_key or not args.api_key_id:
        parser.error("--api-key and --api-key-id are required "
                     "(or set CORTEX_API_KEY and CORTEX_API_KEY_ID).")
    if args.only:
        known = {n.lower() for n, *_ in QUERIES} | {"hostinventory.csv", "app-inventory.csv",
                                                     "mgmtactivity.csv"}
        unknown = [n for n in (x.strip() for x in args.only.split(",")) if n.lower() not in known]
        if unknown:
            parser.error(f"--only: unknown output file(s): {', '.join(unknown)}")

    run(args)


if __name__ == "__main__":
    main()
