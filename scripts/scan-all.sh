#!/bin/bash
set -e

IMAGE_NAME=${1:-vulnerable-flask-app:v1.0}
OUTPUT_DIR=${2:-scans}

echo "🚀 Starting comprehensive security scan for: $IMAGE_NAME"
echo "=================================================="

# Create output directories
mkdir -p $OUTPUT_DIR/{trivy,grype,sbom,hadolint,summary}

# 1. Trivy Scans
echo ""
echo "1️⃣ Running Trivy vulnerability scan..."
trivy image --severity CRITICAL,HIGH,MEDIUM \
  --format json \
  --output $OUTPUT_DIR/trivy/vulnerabilities.json \
  $IMAGE_NAME

trivy image --severity CRITICAL,HIGH \
  $IMAGE_NAME | tee $OUTPUT_DIR/trivy/summary.txt

# 2. Secret Detection
echo ""
echo "2️⃣ Scanning for secrets..."
trivy image --scanners secret \
  --format json \
  --output $OUTPUT_DIR/trivy/secrets.json \
  $IMAGE_NAME

# 3. Grype Scan
echo ""
echo "3️⃣ Running Grype scan..."
grype $IMAGE_NAME \
  --output json \
  --file $OUTPUT_DIR/grype/vulnerabilities.json

# 4. SBOM Generation
echo ""
echo "4️⃣ Generating SBOM..."
syft $IMAGE_NAME \
  --output cyclonedx-json \
  --file $OUTPUT_DIR/sbom/cyclonedx.json

syft $IMAGE_NAME \
  --output spdx-json \
  --file $OUTPUT_DIR/sbom/spdx.json

# 5. Dockerfile Linting (if Dockerfile exists)
if [ -f "vulnerable-app/Dockerfile" ]; then
    echo ""
    echo "5️⃣ Linting Dockerfile..."
    hadolint vulnerable-app/Dockerfile > $OUTPUT_DIR/hadolint/results.txt || true
fi

# 6. Generate Summary Report
echo ""
echo "6️⃣ Generating summary report..."

cat > $OUTPUT_DIR/summary/report.md 

# Container Security Scan Report

## Scan Date
$(date)

## Image Scanned
$IMAGE_NAME

## Findings Summary

### Critical Vulnerabilities
$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)

### High Vulnerabilities
$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="HIGH")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)

### Medium Vulnerabilities
$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="MEDIUM")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)

### Secrets Found
$(jq '[.Results[].Secrets[]] | length' $OUTPUT_DIR/trivy/secrets.json 2>/dev/null || echo "0")

### Dockerfile Issues
$(wc -l < $OUTPUT_DIR/hadolint/results.txt)

### Total Packages
$(jq '.components | length' $OUTPUT_DIR/sbom/cyclonedx.json)

## Detailed Findings

See individual scan results in:
- Trivy: $OUTPUT_DIR/trivy/
- Grype: $OUTPUT_DIR/grype/
- SBOM: $OUTPUT_DIR/sbom/
- Hadolint: $OUTPUT_DIR/hadolint/

REPORT_EOF

echo ""
echo "✅ Scan complete! Results saved to: $OUTPUT_DIR/"
echo ""
echo "📊 Quick Summary:"
echo "   Critical: $(jq '[.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)"
echo "   High: $(jq '[.Results[].Vulnerabilities[] | select(.Severity=="HIGH")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)"
echo "   Medium: $(jq '[.Results[].Vulnerabilities[] | select(.Severity=="MEDIUM")] | length' $OUTPUT_DIR/trivy/vulnerabilities.json)"
echo "   Secrets: $(jq '[.Results[].Secrets[]] | length' $OUTPUT_DIR/trivy/secrets.json 2>/dev/null || echo "0")"
EOF

