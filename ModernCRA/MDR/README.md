# MDR Assessment Toolkit

<!-- (c) 2026, Shane D. Shook, PhD -->

This folder contains tools for conducting cyber risk assessments using Managed Detection and Response (MDR) platforms.

## Contents

| File | Description |
|------|-------------|
| `s1_query_runner.py` | Automated SentinelOne (S1) data collection script |
| `CS_query_runner.py` | Automated CrowdStrike (CS) data collection script |
| `cortex_query_runner.py` | Automated Palo Alto Cortex XDR data collection script |
| `s1queries.txt` | Manual SentinelOne query reference (Deep Visibility) |
| `AnalysisPrompt.txt` | AI prompt template for generating assessment reports |

---

## Quick Start

### SentinelOne (S1)

```bash
python s1_query_runner.py \
    --url https://YOUR-TENANT.sentinelone.net \
    --token YOUR_API_TOKEN \
    --days 90 \
    --output ./s1_assessment_output
```

### CrowdStrike (CS)

```bash
python CS_query_runner.py \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET \
    --base-url https://api.crowdstrike.com \
    --days 90 \
    --output ./cs_assessment_output
```

### Palo Alto Cortex XDR

```bash
python cortex_query_runner.py \
    --fqdn YOUR-TENANT.xdr.us.paloaltonetworks.com \
    --api-key YOUR_API_KEY \
    --api-key-id YOUR_API_KEY_ID \
    --days 90 \
    --output ./cortex_assessment_output
```

---

## Detailed Usage

### SentinelOne (S1) Query Runner

The `s1_query_runner.py` script automates data collection from SentinelOne via the Deep Visibility and Management APIs.

#### Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--url` | ✅ | — | SentinelOne console base URL |
| `--token` | ✅ | — | API token |
| `--days` | ❌ | 90 | Look-back window (if dates not specified) |
| `--from-date` | ❌ | — | Query start (ISO-8601 UTC) |
| `--to-date` | ❌ | — | Query end (ISO-8601 UTC) |
| `--output` | ❌ | `./assessment_output` | Output directory |

#### Examples

```bash
# Last 90 days (default)
python s1_query_runner.py \
    --url https://tenant.sentinelone.net \
    --token YOUR_API_TOKEN

# Specific date range
python s1_query_runner.py \
    --url https://tenant.sentinelone.net \
    --token YOUR_API_TOKEN \
    --from-date 2026-02-25T00:00:00Z \
    --to-date 2026-05-25T23:59:59Z

# Custom output directory with 30-day window
python s1_query_runner.py \
    --url https://tenant.sentinelone.net \
    --token YOUR_API_TOKEN \
    --days 30 \
    --output ./acme_assessment_2026-05
```

---

### CrowdStrike (CS) Query Runner

The `CS_query_runner.py` script automates data collection from CrowdStrike Falcon via the OAuth2 REST API and NGSIEM (LogScale).

#### Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--client-id` | ✅ | — | CrowdStrike OAuth2 client ID |
| `--client-secret` | ✅ | — | CrowdStrike OAuth2 client secret |
| `--base-url` | ❌ | `https://api.crowdstrike.com` | Falcon API base URL |
| `--days` | ❌ | 90 | Look-back window (if dates not specified) |
| `--from-date` | ❌ | — | Query start (ISO-8601 UTC) |
| `--to-date` | ❌ | — | Query end (ISO-8601 UTC) |
| `--output` | ❌ | `./cs_assessment_output` | Output directory |

#### CrowdStrike Cloud Regions

| Region | Base URL |
|--------|----------|
| US-1 (default) | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

#### Examples

```bash
# Last 90 days, US-1 cloud (default)
python CS_query_runner.py \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET

# Specific date range
python CS_query_runner.py \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET \
    --from-date 2026-02-25T00:00:00Z \
    --to-date 2026-05-25T23:59:59Z

# EU-1 cloud, custom output directory
python CS_query_runner.py \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET \
    --base-url https://api.eu-1.crowdstrike.com \
    --output ./acme_assessment_may2026
```

---

### Cortex XDR Query Runner

The `cortex_query_runner.py` script automates data collection from Cortex XDR via the public REST API. Event queries are XQL run against the `xdr_data` dataset using the async start → poll → fetch pattern, with the streaming endpoint used automatically for result sets over 1,000 rows.

#### Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--fqdn` | ✅ | — | Tenant FQDN (e.g. `acme.xdr.us.paloaltonetworks.com`). `https://api-` is added; a value starting `api-` or `http(s)://` is used as given |
| `--api-key` | ✅* | `$CORTEX_API_KEY` | API key |
| `--api-key-id` | ✅* | `$CORTEX_API_KEY_ID` | API key ID |
| `--auth-type` | ❌ | `standard` | `standard` or `advanced` — must match how the key was created |
| `--days` | ❌ | 90 | Look-back window (if dates not specified) |
| `--from-date` | ❌ | — | Query start (ISO-8601 UTC) |
| `--to-date` | ❌ | — | Query end (ISO-8601 UTC) |
| `--output` | ❌ | `./cortex_assessment_output` | Output directory |
| `--only` | ❌ | all | Comma-separated output file names to collect, e.g. `Beacons.csv,RmmUse.csv` |

\* Required, either as an option or from the environment variable. Prefer the environment variables so the key stays out of the shell history and process list.

#### Examples

```bash
# Last 90 days, standard key
python cortex_query_runner.py \
    --fqdn acme.xdr.us.paloaltonetworks.com \
    --api-key YOUR_API_KEY --api-key-id YOUR_API_KEY_ID

# Advanced key, credentials from the environment, specific window
export CORTEX_API_KEY=YOUR_API_KEY CORTEX_API_KEY_ID=YOUR_API_KEY_ID
python cortex_query_runner.py \
    --fqdn acme.xdr.us.paloaltonetworks.com \
    --auth-type advanced \
    --from-date 2026-02-25T00:00:00Z \
    --to-date 2026-05-25T23:59:59Z

# Re-run only some outputs over a shorter window
python cortex_query_runner.py \
    --fqdn acme.xdr.us.paloaltonetworks.com \
    --only Beacons.csv,RmmUse.csv --days 30
```

#### Differences from the S1 and CS Runners

The output files use the same names so `AnalysisPrompt.txt` applies unchanged, but Cortex XDR does not record identical data, so some queries are approximations. These are stated in each query's description in the CoC manifest and in the source comments:

| Output | Cortex approach |
|--------|-----------------|
| `UPPCount.csv`, `UPPActivity.csv` | Process-start activity per user per host. Logon events need Windows Event Log collection, which is not on by default |
| `CredentialTheft.csv` | Credential-dumping command lines (mimikatz, comsvcs MiniDump, `reg save sam`, ntdsutil…). Raw LSASS handle opens are not matched |
| `BackdoorsIn.csv` | Inbound direction is inferred from the port pattern (low local port, ephemeral remote port) |
| `PrivilegeRisks.csv` | Non-SYSTEM parents starting SYSTEM-context processes, with raw integrity-level values included |
| `Rootkits.csv` | `.sys` module loads from outside the standard driver locations |
| `SchTasks.csv`, `NewServices.csv` | Derived from `schtasks` / `sc` / PowerShell command lines |
| `app-inventory.csv` | XQL `host_inventory_applications` preset; needs the Host Insights add-on |

#### Query Quota

XQL API queries consume Cortex query quota, and at most four run in parallel per tenant (the script runs them one at a time). The remaining quota and per-query cost are recorded in `chain_of_custody.json`. On a large tenant use a shorter `--days` window, or `--only`. The summary logs a quota-remaining figure when Cortex reports one.

---

## API Token Generation & Setup

### SentinelOne (S1) — Generating an API Token

If you only have username/password/MFA access to the SentinelOne console:

#### Step 1: Log into the SentinelOne Console

1. Navigate to your tenant URL: `https://YOUR-TENANT.sentinelone.net`
2. Enter your username and password
3. Complete MFA authentication if prompted

#### Step 2: Generate an API Token

1. Click on your **user icon** (top-right corner) → **My User**
2. Scroll down to the **API Token** section
3. Click **Generate** (or **Regenerate** if one exists)
4. **Copy and save the token immediately** — it will only be displayed once
5. Set an appropriate expiration period based on your assessment timeline

#### Step 3: Gather Required Information

| Information Needed | Where to Find It |
|--------------------|------------------|
| **Console URL** | The URL in your browser address bar (e.g., `https://usea1-acme.sentinelone.net`) |
| **API Token** | Generated in Step 2 above |

#### API Scopes Required

The user account generating the token needs these permissions:
- **Deep Visibility** — Read (for threat-hunting queries)
- **Endpoints** — Read (for host inventory)
- **Applications** — Read (for application inventory)
- **Activity Log** — Read (for management activity)

> **Note:** If your user role doesn't have sufficient permissions, contact your SentinelOne administrator to request a Service User with the appropriate scope, or ask for elevated permissions on your account.

---

### CrowdStrike (CS) — Generating API Credentials

If you only have username/password/MFA access to the Falcon console:

#### Step 1: Log into the Falcon Console

1. Navigate to your Falcon console (e.g., `https://falcon.crowdstrike.com` or your regional URL)
2. Enter your username and password
3. Complete MFA authentication if prompted

#### Step 2: Create an OAuth2 API Client

1. Click the **menu icon** (☰) → **Support and resources** → **API clients and keys**
   - Or navigate directly to: **Falcon Console** → **Support** → **API Clients and Keys**
2. Click **Add new API client**
3. Configure the client:
   - **Client name:** `CRA-Assessment-Client` (or similar descriptive name)
   - **Description:** `Cyber Risk Assessment data collection`
4. Select the following **API Scopes** (Read permissions):

| Scope | Permission | Purpose |
|-------|------------|---------|
| **Hosts** | Read | Device inventory |
| **NGSIEM / LogScale** | Read + Write | CQL query submission and retrieval |
| **Falcon Discover (Assets)** | Read | Application inventory |
| **Event Streams** | Read | Management activity audit log |
| **Audit Events** | Read | Additional audit logging (if available) |

5. Click **Add**
6. **Copy and securely store:**
   - **Client ID**
   - **Client Secret** (displayed only once!)

#### Step 3: Gather Required Information

| Information Needed | Where to Find It |
|--------------------|------------------|
| **Client ID** | Displayed after API client creation |
| **Client Secret** | Displayed once after creation — copy immediately |
| **Base URL** | Determined by your cloud region (see table above) |

To determine your cloud region:
1. Look at your Falcon console URL
2. Or go to **Support** → **API Clients and Keys** and check the displayed base URL

#### API Client Permissions Summary

```
Hosts                     : Read
Event Streams             : Read
NGSIEM / LogScale         : Read + Write
Falcon Discover (Assets)  : Read
Audit Events              : Read
```

> **Note:** The **Write** permission for NGSIEM is required to submit search jobs. Without it, the script cannot execute CQL queries.

---

### Cortex XDR — Generating an API Key

If you only have username/password/MFA access to the Cortex XDR console:

#### Step 1: Create the API Key

1. Log in to the Cortex XDR console and complete MFA.
2. Go to **Settings** → **Configurations** → **Integrations** → **API Keys**.
3. Click **New Key**.
4. Choose the **Security Level**:
   - **Standard** — the key is sent as-is in the `Authorization` header (use `--auth-type standard`).
   - **Advanced** — each request is signed with a nonce and timestamp (use `--auth-type advanced`).
5. Set an expiration that covers the assessment, and a **Role** of **Instance Administrator** (required to run XQL API queries), or a custom role permitting XQL queries, endpoint read and audit-log read.
6. Click **Generate** and **copy the key immediately** — it is shown only once.

#### Step 2: Get the Key ID and Tenant FQDN

| Information Needed | Where to Find It |
|--------------------|------------------|
| **API Key ID** | The **ID** column of the API Keys table |
| **Tenant FQDN** | Right-click the **Copy API URL** action on the API Keys page; the host looks like `api-acme.xdr.us.paloaltonetworks.com`. Pass it to `--fqdn` with or without the `api-` prefix |

#### Other Requirements

| Item | Needed for |
|------|------------|
| Cortex XDR license | All collection |
| Host Insights add-on | `app-inventory.csv` only. Without it that file is reported as failed in the manifest and can be exported manually from the console |
| Available XQL query quota | All XQL queries |

---

## Output Files

All scripts generate:

1. **Individual CSV files** for each query category (LVL1–LVL5)
2. **Inventory exports:**
   - `HostInventory.csv` — Endpoint/device inventory
   - `app-inventory.csv` — Application inventory
   - `MgmtActivity.csv` — Management/audit activity log
3. **`chain_of_custody.json`** — Signed manifest with SHA-256 hashes for integrity verification

### Query Risk Levels

| Level | Category | Examples |
|-------|----------|----------|
| LVL1 | Data Transfer & Tool Risk | Cloud storage, AI tools, USB usage |
| LVL2 | User Activity & Credential Risk | Profile propagation, credential theft, lateral movement |
| LVL3 | Network Risk | Tunnels, beacons, backdoors, suspicious DNS |
| LVL4 | Service & Configuration Risk | RMM tools, LOLBins, process injection, scheduled tasks |
| LVL5 | Build & Posture | OS versions, endpoint health, application inventory |

---

## Analysis Workflow

1. **Run the appropriate script** for your tenant type (S1, CS or Cortex)
2. **Review the chain-of-custody manifest** for collection status and any errors
3. **Add any manual exports** if required (e.g., Entra ID data)
4. **Use `AnalysisPrompt.txt`** with your preferred AI assistant to generate the assessment report
5. **Review and customize** the generated report for your client

---

## Supplementary Files

### s1queries.txt

A comprehensive reference of SentinelOne Deep Visibility queries organized by risk level. Use this for:
- Manual query execution in the console
- Understanding query logic
- Customizing queries for specific environments

### AnalysisPrompt.txt

A detailed prompt template for generating professional cyber risk assessment reports. Includes:
- Executive summary guidance
- Technical findings structure
- OSINT threat correlation
- Priority remediation roadmap
- Supporting references and appendices

---

## Requirements

```bash
pip install requests
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **401 Unauthorized** | Token expired or invalid — regenerate API token/credentials. Cortex: also check `--auth-type` matches the key's security level and the key ID is correct |
| **403 Forbidden** | Insufficient API scope permissions — verify required scopes |
| **Connection timeout** | Check network connectivity and firewall rules |
| **Rate limiting (429)** | Wait and retry — scripts include automatic backoff |
| **Empty results** | Verify date range and check if data exists for the query |
| **Cortex: one XQL query fails** | The `note` for that file in `chain_of_custody.json` holds the reason (syntax, dataset access, quota). Fix the query in `cortex_query_runner.py` and re-run just that file with `--only` |
| **Cortex: `app-inventory.csv` fails** | The Host Insights add-on is not licensed or enabled — export Host Inventory → Applications from the console |

### Token Refresh (CrowdStrike)

CrowdStrike OAuth2 tokens have a 30-minute TTL. The script automatically refreshes tokens before expiration.

### Logging

All scripts output detailed logging to stdout. Redirect to a file for troubleshooting:

```bash
python s1_query_runner.py --url ... --token ... 2>&1 | tee collection.log
python CS_query_runner.py --client-id ... --client-secret ... 2>&1 | tee collection.log
python cortex_query_runner.py --fqdn ... --api-key ... --api-key-id ... 2>&1 | tee collection.log
```

---

## Notes

- Queries are tailored for comprehensive cyber risk assessment
- Modify queries as needed for specific environment requirements  
- Data quality notes in `AnalysisPrompt.txt` address known query limitations
- Always secure API credentials — never commit them to version control
