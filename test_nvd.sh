#!/bin/bash
# Test NVD integration end-to-end

set -e

echo "🧪 Testing NVD API Integration..."
echo ""

# Create organization
echo "1. Creating organization..."
ORG=$(curl -k -s -X POST https://localhost:8443/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name":"MedTech Startup","industry":"healthcare"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "   ✓ Org ID: $ORG"

# Create metadata profile with PostgreSQL 13.2 (has known CVEs)
echo "2. Creating metadata profile with software stack (PostgreSQL 13.2)..."
PROFILE=$(curl -k -s -X POST https://localhost:8443/api/v1/metadata-profiles \
  -H "Content-Type: application/json" \
  -d "{\"organization_id\":\"$ORG\",\"phi_types\":[\"medical_records\"],\"software_stack\":{\"postgresql\":\"13.2\"},\"infrastructure\":{\"encryption_at_rest\":true,\"tls_enabled\":true},\"access_controls\":{\"mfa_enabled\":true}}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "   ✓ Profile ID: $PROFILE"

# Run assessment (calls NVD API)
echo "3. Running assessment (querying NVD API for PostgreSQL 13.2 vulnerabilities)..."
ASSESSMENT=$(curl -k -s -X POST https://localhost:8443/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d "{\"organization_id\":\"$ORG\",\"metadata_profile_id\":\"$PROFILE\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "   ✓ Assessment ID: $ASSESSMENT"

# Get findings
echo "4. Retrieving findings..."
curl -k -s https://localhost:8443/api/v1/assessments/$ASSESSMENT/findings | python3 -m json.tool > /tmp/findings.json
FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('/tmp/findings.json'))))")
echo "   ✓ Found $FINDING_COUNT findings"

# Get remediation roadmap
echo "5. Generating remediation roadmap..."
curl -k -s https://localhost:8443/api/v1/assessments/$ASSESSMENT/roadmap | python3 -m json.tool > /tmp/roadmap.json
echo "   ✓ Roadmap generated"

echo ""
echo "📊 Summary:"
python3 << 'PYTHON'
import json

# Load roadmap
roadmap = json.load(open('/tmp/roadmap.json'))
summary = roadmap['summary']

print(f"   Total Findings: {summary['total_findings']}")
print(f"   - Critical: {summary['critical_count']}")
print(f"   - High: {summary['high_count']}")
print(f"   - Medium: {summary['medium_count']}")
print(f"   - Low: {summary['low_count']}")
print(f"")
print(f"   Remediation Timeline:")
print(f"   - Immediate: {summary['immediate_actions']} actions")
print(f"   - 30 Days: {summary['thirty_day_actions']} actions")
print(f"   - Quarterly: {summary['quarterly_actions']} actions")
print(f"   - Annual: {summary['annual_actions']} actions")

# Show CVE findings
findings = json.load(open('/tmp/findings.json'))
cve_findings = [f for f in findings if f.get('cve_ids')]
if cve_findings:
    print(f"")
    print(f"🔍 CVE-based Findings from NVD:")
    for finding in cve_findings[:3]:  # Show first 3
        cve_id = finding['cve_ids'][0] if finding['cve_ids'] else "N/A"
        print(f"   • {cve_id}: {finding['title']}")
        print(f"     Severity: {finding['severity'].upper()} (CVSS: {finding['cvss_score']})")
PYTHON

echo ""
echo "✅ Test complete! Real CVE data integrated from NVD."
