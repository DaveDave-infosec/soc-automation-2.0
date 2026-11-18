# SOC Automation 2.0 — Splunk Threat Detection & AI-Assisted Triage

**Hands-on SOC lab | Splunk Free | n8n | Windows Security Events | AbuseIPDB | OpenAI | Slack**

Built an automated security monitoring pipeline that queries Splunk for Windows failed-logon bursts, filters non-public source IPs, enriches eligible IPs with AbuseIPDB, requests an AI-assisted analyst summary, and posts a structured notification to Slack.

> **Lab scope:** A genuine Windows failed-logon detection was verified in Splunk. The full **eight-node** enrichment-to-Slack path was separately tested with **explicitly simulated** public-IP detection data. This is a portfolio demonstration, not proof of a real external brute-force attack or a production-hardened SOC deployment.

## Architecture

```text
Windows FLARE-VM
  | Windows Security Event ID 4625
  v
Splunk Universal Forwarder --> Splunk Enterprise (Free license; index=main)
                                 ^
                                 | REST export search on localhost:8089
                                 | via restricted service-account script
                                 |
n8n Schedule Trigger (every 5 min)
  --> SSH: run detection script
  --> JavaScript: parse JSON result
  --> JavaScript: filter non-public IPv4
  --> AbuseIPDB: check eligible public source IP
  --> JavaScript: classify reputation score
  --> OpenAI GPT-5 Mini: SOC assessment
  --> Slack: #soc-alerts
```

**Components:** VMware-based Windows FLARE-VM with Splunk Universal Forwarder, Ubuntu Splunk server, separate Ubuntu/Docker n8n server, AbuseIPDB REST API, OpenAI API, and a Slack bot. The project uses Splunk Free, where native scheduled alerts are unavailable; **n8n supplies the schedule instead**.

## Detection logic

The script searches `index=main` for Event ID `4625` from the lab Windows host, resolves `Source_Network_Address` or `src_ip`, groups events into five-minute Splunk time buckets, and selects **three or more failed logons from the same IP on the same host**.

```spl
search index=main host="DESKTOP-6GS2V0M" source="WinEventLog:Security" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, src_ip)
| bin _time span=5m
| stats count AS failed_attempts by _time, host, source_ip
| where failed_attempts >= 3
| table _time, host, source_ip, failed_attempts
```

The scheduled script queries the **last five minutes**. Search results are returned as newline-delimited JSON by Splunk's `/services/search/jobs/export` REST endpoint. The parser produces `host`, `source_ip`, `timestamp`, `failed_attempts`, and `alert_type` records; no matching result means no downstream API calls.

**Timing limitation:** Five-minute search windows and five-minute `bin` buckets are not the same thing. Failures spread across bucket boundaries, delayed ingestion, and scheduling jitter can cause missed detections. Equal search/schedule durations also do not guarantee reliable deduplication. A production implementation should use overlapping windows with a persisted alert identifier/watermark and explicit late-arrival handling.

## Why Splunk REST rather than CLI?

The local CLI executed successfully but repeatedly returned zero results for Event ID 4625, despite three matching events appearing in Splunk Web. The authenticated **REST export search** returned the expected `failed_attempts=3`. To use that reliable path, the n8n SSH node executes a root-owned shell script as the `splunk` service account through a **single-command, passwordless sudo rule**. API credentials are in a protected local file, not in the published workflow.

See [`splunk/n8n-splunk-detection.example.sh`](splunk/n8n-splunk-detection.example.sh) for a redacted example. It expects a separately provisioned curl credentials file and must be adapted to the deployment.

## n8n workflow

[**Sanitized, importable n8n workflow JSON**](SOC_Automation_2_GitHub_Sanitized.json)

| Stage | Function |
|---|---|
| 1. Schedule Trigger | Run every five minutes |
| 2. Execute a command (SSH) | Invoke the Splunk REST detection script |
| 3. Code in JavaScript | Parse Splunk's JSON; stop on SSH errors and empty results |
| 4. Filter Public IPs | Skip local/non-public IPv4 addresses before enrichment |
| 5. AbuseIPDB IP Reputation Check | Query `/api/v2/check` with `maxAgeInDays=90` |
| 6. Code in JavaScript1 | Extract confidence score/report count; lab thresholds: low 0–24, medium 25–74, high 75–100 |
| 7. AI SOC Threat Assessment | GPT-5 Mini summarizes evidence and suggests analyst actions |
| 8. Send SOC Alert to Slack | Post detection details, reputation context, and AI assessment |

The score bands are **custom lab heuristics**, not AbuseIPDB's official risk levels. Reputation scores alone neither prove maliciousness nor establish that an IP is safe. The AI is instructed not to invent evidence or recommend automatic blocking on insufficient information.

The exported IP filter is a **simplified IPv4-only lab filter**, not a complete routability validator. For production, use a maintained IP-address library and explicit IPv6 handling.

## Verification and evidence

| Test | Observed outcome |
|---|---|
| Windows failed-logon audit | `auditpol` confirmed Success and Failure logging |
| Real local authentication test | Three Event ID `4625` events recorded after controlled incorrect sign-ins |
| Splunk ingestion and SPL | Three new failed logons appeared in the same five-minute bucket on the Windows lab host |
| Real source-IP extraction | The three local attempts showed `127.0.0.1` |
| Non-public IP filter | `127.0.0.1` was correctly excluded from AbuseIPDB |
| REST detection | Historical REST query found three grouped failures; unattended script authentication and execution succeeded |
| Live AbuseIPDB lookup | A controlled lookup of public DNS IP `8.8.8.8` returned an API response and was parsed successfully |
| Live OpenAI API | GPT-5 Mini generated an analyst-style assessment from clearly identified synthetic event details |
| Slack bot | A test notification was delivered to `#soc-alerts` |
| Complete eight-node path | Successful execution using **pinned simulated SSH output**, with the Slack alert labeled **SIMULATED LAB TEST** |
| Published schedule | n8n execution history showed successful runs approximately five minutes apart, with no downstream calls when there was no detection |

**Critical distinction:** `8.8.8.8` was used only to exercise the public-IP enrichment path; it was **not** observed attacking the Windows host. The actual local failed logons originated from `127.0.0.1`. The full end-to-end alert is therefore a **simulation**, not a real-world intrusion finding.

### Screenshots

Evidence screenshots were captured during testing (Splunk events, n8n execution graph, AbuseIPDB, AI response, and the simulated Slack alert). They are **not yet included in this repository**. No screenshots have been fabricated or represented as committed evidence.

## Reproducing the lab

1. Deploy a Windows endpoint and forward `WinEventLog:Security` into a Splunk index. Enable failed-logon auditing and verify Event ID `4625`.
2. Deploy n8n (Docker is suitable) and import [the sanitized workflow](SOC_Automation_2_GitHub_Sanitized.json).
3. On the Splunk host, place an adapted detection script under an administrator-controlled path. Give the n8n SSH user permission to execute **only that fixed script** as the Splunk service account, not arbitrary root commands.
4. Provide a service-account-readable curl configuration **outside the repository** for Splunk REST API authentication. Limit filesystem permissions.
5. Reconnect n8n credentials for SSH, AbuseIPDB Header Auth (`Key`), OpenAI, and Slack. Replace the placeholder Slack channel ID with the target channel's real ID and invite the bot to that channel.
6. Replace lab-specific hostnames and script paths. Review the SPL logic and IP ranges for your own environment.
7. Run controlled tests; label simulated events and verify that empty detections do **not** trigger API calls. Remove pinned test outputs before enabling the schedule.
8. Publish only when ready. Monitor n8n executions and API usage/billing.

**Security notes:** Never commit tokens, passwords, protected curl configuration files, n8n credential stores, or unredacted live exports. The sanitized JSON contains credential placeholders rather than usable secrets. The local REST example uses `curl -k` for lab TLS; production should validate certificates. Keep n8n's HTTP management interface private and secure it with TLS before any external exposure.

## Limitations and next improvements

- The project **does not automatically block IPs, isolate hosts, or prove account compromise**.
- No demonstrated live external attack traversed AbuseIPDB → OpenAI → Slack; that path was validated with **simulated source data**.
- Basic thresholding can miss activity across bucket boundaries; add overlap, alert deduplication, late-event handling, and alert-state persistence.
- Improve the IP filter for all special-purpose IPv4 ranges and IPv6, and add missing-IP handling.
- Add retry/backoff and failure notifications for REST/API/SSH steps, rate limiting, API spending limits, and retention policies.
- Consider source-IP trust context (NAT, proxies, VPNs) and enrich with corroborating Windows/network evidence before escalation.

## Skills demonstrated

**Splunk SPL and REST API • Windows auditing • SIEM ingestion • SSH/Linux permissions • n8n orchestration • JSON/JavaScript • IP reputation enrichment • AI-assisted SOC triage • Slack alerting • Controlled testing and evidence-based documentation**

---

**Project:** SOC Automation 2.0 | **Portfolio:** [Cybersecurity Portfolio](https://github.com/DaveDave-infosec/cybersecurity-portfolio)

*Lab-focused implementation. External API services have their own access, usage, and billing requirements.*
