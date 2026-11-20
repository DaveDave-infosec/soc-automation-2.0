# Evidence screenshots

These seven screenshots were captured during the SOC Automation 2.0 lab and are organized by test stage. **The PNG files are stored in the repository root**; follow the links below.

| File | Evidence |
|---|---|
| [\`01_splunk_failed_logins_detected.png\`](../01_splunk_failed_logins_detected.png) | Three genuine Windows Security 4625 failed logons grouped by Splunk |
| [\`02_splunk_loopback_source_ip.png\`](../02_splunk_loopback_source_ip.png) | Source address `127.0.0.1` for local failed logons |
| [\`03_n8n_full_eight_node_simulated_execution.png\`](../03_n8n_full_eight_node_simulated_execution.png) | Successful eight-node simulated end-to-end execution |
| [\`04_slack_simulated_alert_summary.png\`](../04_slack_simulated_alert_summary.png) | Slack alert explicitly marked as a simulated lab test |
| [\`05_slack_ai_assessment.png\`](../05_slack_ai_assessment.png) | AI SOC analysis delivered to Slack |
| [\`06_slack_recommendations.png\`](../06_slack_recommendations.png) | Investigation guidance in the simulated Slack alert |
| [\`07_n8n_published_schedule_execution_history.png\`](../07_n8n_published_schedule_execution_history.png) | Published workflow runs approximately five minutes apart |

**Evidence boundary:** Screenshots 01–02 show **real local failed logons**. Screenshots 03–06 demonstrate the **simulated external-IP branch**, not a confirmed external attack. Screenshot 07 verifies scheduled polling.

All seven screenshots have been committed to the repository root and are embedded in the main [README](../README.md).
