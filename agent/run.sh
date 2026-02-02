#!/bin/sh

set -e

BACKEND_ENDPOINT="${BACKEND_ENDPOINT:-http://localhost:18081}"

if [ -z "$CLUSTER_ID" ]; then
  CLUSTER_ID=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')
fi

echo "starting for cluster: $CLUSTER_ID"
echo "backend endpoint: $BACKEND_ENDPOINT"

send_with_retry() {
  ENDPOINT=$1
  DATA=$2
  MAX_RETRIES=5
  RETRY_COUNT=0

  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -X POST "$ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "$DATA" \
      --max-time 10 \
      2>/dev/null; then
      return 0
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    WAIT_TIME=$((15 * RETRY_COUNT))
    echo "retry $RETRY_COUNT/$MAX_RETRIES after ${WAIT_TIME}s..."
    sleep $WAIT_TIME
  done

  echo "failed after $MAX_RETRIES retries"
  return 1
}

while true; do
  echo "running trivy cluster scan"

  TRIVY_OUTPUT=$(timeout 300 trivy k8s cluster --format json --skip-db-update 2>/dev/null || true)
  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 143 ]; then
    echo "trivy scan timed out"
  fi

  if [ -n "$TRIVY_OUTPUT" ]; then
    PAYLOAD=$(echo "$TRIVY_OUTPUT" | jq -c .)
    REQUEST_BODY=$(jq -n \
      --arg cid "$CLUSTER_ID" \
      --arg kind "trivy-scan" \
      --argjson payload "$PAYLOAD" \
      '{cluster_id: $cid, kind: $kind, payload: $payload}')

    send_with_retry "$BACKEND_ENDPOINT/ingest" "$REQUEST_BODY"
  fi

  echo "collecting namespaces"

  NAMESPACES=$(kubectl get namespaces -o json 2>/dev/null || true)

  if [ -n "$NAMESPACES" ]; then
    REQUEST_BODY=$(jq -n \
      --arg cid "$CLUSTER_ID" \
      --arg kind "namespaces" \
      --argjson payload "$NAMESPACES" \
      '{cluster_id: $cid, kind: $kind, payload: $payload}')

    send_with_retry "$BACKEND_ENDPOINT/ingest" "$REQUEST_BODY"
  fi

  echo "collecting workloads"

  DEPLOYMENTS=$(kubectl get deployments --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  STATEFULSETS=$(kubectl get statefulsets --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  DAEMONSETS=$(kubectl get daemonsets --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  REPLICASETS=$(kubectl get replicasets --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')

  WORKLOADS=$(jq -n \
    --argjson deps "$DEPLOYMENTS" \
    --argjson sts "$STATEFULSETS" \
    --argjson ds "$DAEMONSETS" \
    --argjson rs "$REPLICASETS" \
    --argjson pods "$PODS" \
    '{deployments: $deps, statefulsets: $sts, daemonsets: $ds, replicasets: $rs, pods: $pods}')

  REQUEST_BODY=$(jq -n \
    --arg cid "$CLUSTER_ID" \
    --arg kind "workloads" \
    --argjson payload "$WORKLOADS" \
    '{cluster_id: $cid, kind: $kind, payload: $payload}')

  send_with_retry "$BACKEND_ENDPOINT/ingest" "$REQUEST_BODY"

  echo "collecting nodes"

  NODES=$(kubectl get nodes -o json 2>/dev/null || true)

  if [ -n "$NODES" ]; then
    REQUEST_BODY=$(jq -n \
      --arg cid "$CLUSTER_ID" \
      --arg kind "nodes" \
      --argjson payload "$NODES" \
      '{cluster_id: $cid, kind: $kind, payload: $payload}')

    send_with_retry "$BACKEND_ENDPOINT/ingest" "$REQUEST_BODY"
  fi

  echo "scanning images"

  IMAGES=$(kubectl get pods --all-namespaces -o json | \
    jq -r '.items[] | .spec.containers[]?, .spec.initContainers[]? | .image' | \
    sort -u)

  IMAGE_SCANS="["
  FIRST=true

  for IMAGE in $IMAGES; do
    echo "scanning image: $IMAGE"
    SCAN=$(timeout 120 trivy image --quiet --format json "$IMAGE" 2>/dev/null || echo '{}')
    IMAGE_EXIT_CODE=$?
    if [ $IMAGE_EXIT_CODE -eq 124 ] || [ $IMAGE_EXIT_CODE -eq 143 ]; then
      echo "image scan for $IMAGE timed out"
      SCAN='{}'
    fi

    if [ "$FIRST" = true ]; then
      FIRST=false
    else
      IMAGE_SCANS="${IMAGE_SCANS},"
    fi

    IMAGE_SCANS="${IMAGE_SCANS}${SCAN}"
  done

  IMAGE_SCANS="${IMAGE_SCANS}]"

  REQUEST_BODY=$(jq -n \
    --arg cid "$CLUSTER_ID" \
    --arg kind "image-scans" \
    --argjson payload "$IMAGE_SCANS" \
    '{cluster_id: $cid, kind: $kind, payload: $payload}')

  send_with_retry "$BACKEND_ENDPOINT/ingest" "$REQUEST_BODY"

  echo "sleeping for 60 seconds..."
  sleep 60
done
