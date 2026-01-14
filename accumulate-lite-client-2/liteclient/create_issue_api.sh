#!/bin/bash

# GitLab API script to create issue
# You need to set your GitLab personal access token first

echo "This script will create a GitLab issue for the liteclient reorganization"
echo ""
echo "Step 1: Get your GitLab Personal Access Token"
echo "  1. Go to: https://gitlab.com/-/profile/personal_access_tokens"
echo "  2. Create a token with 'api' scope"
echo "  3. Copy the token"
echo ""
read -p "Enter your GitLab Personal Access Token: " GITLAB_TOKEN

# Project ID for accumulatenetwork/core/liteclient
PROJECT_ID="45930495"  # This is the actual project ID

# Create the issue
echo "Creating issue..."

ISSUE_TITLE="Repository Reorganization and Production Proof Implementation (90% Complete)"
ISSUE_DESCRIPTION=$(cat GITLAB_ISSUE.md)

# Make API call
curl --request POST \
  --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --header "Content-Type: application/json" \
  --data "{
    \"title\": \"${ISSUE_TITLE}\",
    \"description\": $(echo "$ISSUE_DESCRIPTION" | jq -Rs .),
    \"labels\": \"Type::Feature,Priority::High,Status::Ready for Review,Component::Lite Client,Cryptography\",
    \"milestone_id\": null,
    \"assignee_id\": null
  }" \
  "https://gitlab.com/api/v4/projects/${PROJECT_ID}/issues"

echo ""
echo "Issue created! Check https://gitlab.com/accumulatenetwork/core/liteclient/-/issues"