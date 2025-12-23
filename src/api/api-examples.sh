#!/bin/bash
#
# VeilKey API Examples
#
# Collection of curl commands to test the VeilKey REST API
# Make sure the server is running: npm run start:api
#

set -e

API_URL="http://localhost:3000"
API_KEY="demo-api-key-12345"

echo "============================================"
echo "VeilKey REST API Examples"
echo "============================================"
echo ""

# Health Check
echo "1. Health Check (no auth required)"
echo "   GET /health"
echo ""
curl -s "$API_URL/health" | jq .
echo ""
echo ""

# Create Key Group
echo "2. Create 2-of-3 Key Group"
echo "   POST /v1/groups"
echo ""
GROUP_RESPONSE=$(curl -s -X POST "$API_URL/v1/groups" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "threshold": 2,
    "parties": 3,
    "algorithm": "RSA-2048"
  }')

echo "$GROUP_RESPONSE" | jq .
GROUP_ID=$(echo "$GROUP_RESPONSE" | jq -r '.id')
echo ""
echo "Created Group ID: $GROUP_ID"
echo ""
echo ""

# Get Key Group
echo "3. Get Key Group (public info only)"
echo "   GET /v1/groups/$GROUP_ID"
echo ""
curl -s "$API_URL/v1/groups/$GROUP_ID" \
  -H "X-API-Key: $API_KEY" | jq .
echo ""
echo ""

# Partial Sign 1
echo "4. Create Partial Signature (Share 1)"
echo "   POST /v1/groups/$GROUP_ID/sign/partial"
echo ""
PARTIAL1=$(curl -s -X POST "$API_URL/v1/groups/$GROUP_ID/sign/partial" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 1
  }')

echo "$PARTIAL1" | jq .
echo ""
echo ""

# Partial Sign 2
echo "5. Create Partial Signature (Share 2)"
echo "   POST /v1/groups/$GROUP_ID/sign/partial"
echo ""
PARTIAL2=$(curl -s -X POST "$API_URL/v1/groups/$GROUP_ID/sign/partial" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 2
  }')

echo "$PARTIAL2" | jq .
echo ""
echo ""

# Combine Signatures
echo "6. Combine Partial Signatures"
echo "   POST /v1/groups/$GROUP_ID/sign/combine"
echo ""

# Extract partials
PARTIAL1_INDEX=$(echo "$PARTIAL1" | jq -r '.index')
PARTIAL1_VALUE=$(echo "$PARTIAL1" | jq -r '.partial')
PARTIAL2_INDEX=$(echo "$PARTIAL2" | jq -r '.index')
PARTIAL2_VALUE=$(echo "$PARTIAL2" | jq -r '.partial')

SIGNATURE_RESPONSE=$(curl -s -X POST "$API_URL/v1/groups/$GROUP_ID/sign/combine" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"message\": \"Hello, VeilKey!\",
    \"partials\": [
      {\"index\": $PARTIAL1_INDEX, \"partial\": \"$PARTIAL1_VALUE\"},
      {\"index\": $PARTIAL2_INDEX, \"partial\": \"$PARTIAL2_VALUE\"}
    ]
  }")

echo "$SIGNATURE_RESPONSE" | jq .
SIGNATURE=$(echo "$SIGNATURE_RESPONSE" | jq -r '.signature')
echo ""
echo ""

# Verify Signature (Valid)
echo "7. Verify Signature (Valid)"
echo "   POST /v1/groups/$GROUP_ID/verify"
echo ""
curl -s -X POST "$API_URL/v1/groups/$GROUP_ID/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"message\": \"Hello, VeilKey!\",
    \"signature\": \"$SIGNATURE\"
  }" | jq .
echo ""
echo ""

# Verify Signature (Invalid)
echo "8. Verify Signature (Wrong Message)"
echo "   POST /v1/groups/$GROUP_ID/verify"
echo ""
curl -s -X POST "$API_URL/v1/groups/$GROUP_ID/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"message\": \"Wrong message!\",
    \"signature\": \"$SIGNATURE\"
  }" | jq .
echo ""
echo ""

# Error: Missing API Key
echo "9. Error Example: Missing API Key"
echo "   POST /v1/groups (no X-API-Key header)"
echo ""
curl -s -X POST "$API_URL/v1/groups" \
  -H "Content-Type: application/json" \
  -d '{
    "threshold": 2,
    "parties": 3,
    "algorithm": "RSA-2048"
  }' | jq .
echo ""
echo ""

# Error: Invalid Request
echo "10. Error Example: Invalid Request"
echo "    POST /v1/groups (threshold > parties)"
echo ""
curl -s -X POST "$API_URL/v1/groups" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "threshold": 5,
    "parties": 3,
    "algorithm": "RSA-2048"
  }' | jq .
echo ""
echo ""

# Error: Not Found
echo "11. Error Example: Key Group Not Found"
echo "    GET /v1/groups/non-existent-id"
echo ""
curl -s "$API_URL/v1/groups/non-existent-id" \
  -H "X-API-Key: $API_KEY" | jq .
echo ""
echo ""

echo "============================================"
echo "Examples Complete!"
echo "============================================"
