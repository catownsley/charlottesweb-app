#!/bin/bash
set -e

echo "=== Creating Organization ==="
ORG_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name": "HealthTech Startup Demo", "industry": "digital_health", "stage": "seed"}')
echo "$ORG_RESPONSE" | python3 -m json.tool
ORG_ID=$(echo "$ORG_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Organization ID: $ORG_ID"

echo ""
echo "=== Creating Metadata Profile with Security Gaps ==="
PROFILE_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/metadata-profiles \
  -H "Content-Type: application/json" \
  -d "{
    \"organization_id\": \"$ORG_ID\",
    \"phi_types\": [\"demographic\", \"clinical\"],
    \"cloud_provider\": \"aws\",
    \"infrastructure\": {
      \"encryption_at_rest\": false,
      \"tls_enabled\": false,
      \"logging_enabled\": false,
      \"log_retention_days\": 0
    },
    \"access_controls\": {
      \"mfa_enabled\": false
    }
  }")
echo "$PROFILE_RESPONSE" | python3 -m json.tool
PROFILE_ID=$(echo "$PROFILE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Profile ID: $PROFILE_ID"

echo ""
echo "=== Running Compliance Assessment ==="
ASSESSMENT_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d "{
    \"organization_id\": \"$ORG_ID\",
    \"metadata_profile_id\": \"$PROFILE_ID\"
  }")
echo "$ASSESSMENT_RESPONSE" | python3 -m json.tool
ASSESSMENT_ID=$(echo "$ASSESSMENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Assessment ID: $ASSESSMENT_ID"

echo ""
echo "=== Retrieving Findings ==="
curl -s "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings" | python3 -m json.tool

echo ""
echo "=== Summary ==="
FINDINGS_COUNT=$(curl -s "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "Total findings: $FINDINGS_COUNT"
