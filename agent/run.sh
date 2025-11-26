#!/bin/sh

set -e

BACKEND_ENDPOINT="${BACKEND_ENDPOINT:-http://localhost:18081}"

if [ -z "$CLUSTER_ID" ]; then
  CLUSTER_ID=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')
fi

echo "starting for cluster: $CLUSTER_ID"
echo "backend endpoint: $BACKEND_ENDPOINT"

while true; do
  echo "running trivy cluster scan"

  TRIVY_OUTPUT=$(timeout 300 trivy k8s cluster --format json --skip-db-update 2>/dev/null || true)

  if [ -n "$TRIVY_OUTPUT" ]; then
    PAYLOAD=$(echo "$TRIVY_OUTPUT" | jq -c .)
    REQUEST_BODY=$(jq -n \
      --arg cid "$CLUSTER_ID" \
      --arg kind "trivy-scan" \
      --argjson payload "$PAYLOAD" \
      '{cluster_id: $cid, kind: $kind, payload: $payload}')

    curl -X POST "$BACKEND_ENDPOINT/ingest" \
      -H "Content-Type: application/json" \
      -d "$REQUEST_BODY" \
      2>/dev/null || echo "failed to send Trivy scan"
  fi

  echo "collecting namespaces"

  NAMESPACES=$(kubectl get namespaces -o json 2>/dev/null || true)

  if [ -n "$NAMESPACES" ]; then
    REQUEST_BODY=$(jq -n \
      --arg cid "$CLUSTER_ID" \
      --arg kind "namespaces" \
      --argjson payload "$NAMESPACES" \
      '{cluster_id: $cid, kind: $kind, payload: $payload}')

    curl -X POST "$BACKEND_ENDPOINT/ingest" \
      -H "Content-Type: application/json" \
      -d "$REQUEST_BODY" \
      2>/dev/null || echo "errror failed to send namespaces"
  fi

  echo "collecting workloads

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

  curl -X POST "$BACKEND_ENDPOINT/ingest" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY" \
    2>/dev/null || echo "Failed to send workloads"

  echo "sleeping for 60 seconds..."
  sleep 60
done
