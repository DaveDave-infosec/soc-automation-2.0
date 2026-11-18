#!/usr/bin/env bash
# Example only. Adapt host, credentials path and script installation to your own lab.
# No real credentials are included in this repository.
set -euo pipefail

# Create a protected curl config on the Splunk VM, e.g.:
#   user = "YOUR_SPLUNK_API_USERNAME:YOUR_SPLUNK_API_PASSWORD"
# Never commit that file or include secrets in n8n workflow expressions.
CURL_CONFIG="/opt/splunk/etc/n8n-api-credentials"
SPLUNK_API="https://127.0.0.1:8089/services/search/jobs/export"

exec curl -k -sS --fail   --config "$CURL_CONFIG"   "$SPLUNK_API"   --data-urlencode 'search=search index=main host="YOUR_WINDOWS_HOST" source="WinEventLog:Security" EventCode=4625 | eval source_ip=coalesce(Source_Network_Address, src_ip) | bin _time span=5m | stats count AS failed_attempts by _time, host, source_ip | where failed_attempts >= 3 | table _time, host, source_ip, failed_attempts'   --data-urlencode 'earliest_time=-5m'   --data-urlencode 'latest_time=now'   --data-urlencode 'output_mode=json'
