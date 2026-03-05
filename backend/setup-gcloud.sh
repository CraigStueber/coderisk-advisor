#!/bin/bash
# CodeRisk Advisor — Google Cloud Setup
# -----------------------------------------------
# Run this once to configure your GCP project.
# After this, deployments are handled by the GitHub Actions workflow
# or manually via: gcloud run services replace cloudrun.yaml
#
# Prerequisites:
#   gcloud CLI installed and authenticated
#   Docker installed (for local builds)
#   A GCP project created
#
# Usage:
#   chmod +x setup-gcloud.sh
#   ./setup-gcloud.sh

set -e

# -----------------------------------------------
# CONFIGURE THESE
# -----------------------------------------------
PROJECT_ID="coderisk-advisor"
REGION="us-central1"
SERVICE_NAME="coderisk-advisor"
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME"

# -----------------------------------------------
# SET PROJECT
# -----------------------------------------------
echo "Setting GCP project to $PROJECT_ID..."
gcloud config set project $PROJECT_ID

# -----------------------------------------------
# ENABLE REQUIRED APIS
# -----------------------------------------------
echo "Enabling required GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  containerregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com

# -----------------------------------------------
# CREATE SECRETS IN SECRET MANAGER
# Secrets are never stored in the image or repo.
# You will be prompted to paste each value.
# -----------------------------------------------
echo ""
echo "Creating secrets in Secret Manager..."
echo "You will be prompted to paste each API key."
echo ""

create_secret() {
  local NAME=$1
  local PROMPT=$2
  echo -n "$PROMPT: "
  read -s VALUE
  echo ""

  # Create secret if it doesn't exist
  if ! gcloud secrets describe $NAME --project=$PROJECT_ID &>/dev/null; then
    echo "$VALUE" | gcloud secrets create $NAME \
      --data-file=- \
      --replication-policy="automatic" \
      --project=$PROJECT_ID
    echo "Created secret: $NAME"
  else
    # Add new version if secret already exists
    echo "$VALUE" | gcloud secrets versions add $NAME \
      --data-file=- \
      --project=$PROJECT_ID
    echo "Updated secret: $NAME"
  fi
}

create_secret "openai-api-key" "Paste your OpenAI API key"
create_secret "anthropic-api-key" "Paste your Anthropic API key"
create_secret "langsmith-api-key" "Paste your LangSmith API key"

# -----------------------------------------------
# GRANT CLOUD RUN ACCESS TO SECRETS
# -----------------------------------------------
echo ""
echo "Granting Cloud Run service account access to secrets..."

PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
SA="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"

for SECRET in openai-api-key anthropic-api-key langsmith-api-key; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor" \
    --project=$PROJECT_ID
  echo "Granted access to: $SECRET"
done

# -----------------------------------------------
# BUILD AND PUSH DOCKER IMAGE
# -----------------------------------------------
echo ""
echo "Building and pushing Docker image..."
gcloud auth configure-docker --quiet
docker build -t $IMAGE .
docker push $IMAGE

# -----------------------------------------------
# FIRST DEPLOY
# -----------------------------------------------
echo ""
echo "Deploying to Cloud Run..."

# Replace YOUR_PROJECT_ID placeholder in cloudrun.yaml
sed "s/YOUR_PROJECT_ID/$PROJECT_ID/g" cloudrun.yaml > cloudrun.resolved.yaml

gcloud run services replace cloudrun.resolved.yaml --region=$REGION
rm cloudrun.resolved.yaml

# Make service publicly accessible
gcloud run services add-iam-policy-binding $SERVICE_NAME \
  --region=$REGION \
  --member="allUsers" \
  --role="roles/run.invoker"

# -----------------------------------------------
# DONE
# -----------------------------------------------
echo ""
echo "Deployment complete."
echo ""
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format="value(status.url)")
echo "Service URL: $SERVICE_URL"
echo ""
echo "Next steps:"
echo "  1. Add $SERVICE_URL to your Cloudflare frontend as VITE_API_URL"
echo "  2. Verify LangSmith traces at https://smith.langchain.com"
echo "  3. Test health endpoint: curl $SERVICE_URL/api/health"