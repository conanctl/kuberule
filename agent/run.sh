#!/bin/sh

set -e

BACKEND_ENDPOINT="${BACKEND_ENDPOINT:-http://localhost:18081}"
COLLECTORS_FILE="${COLLECTORS_FILE:-/app/collectors.yaml}"

if [ -z "$CLUSTER_ID" ]; then
  CLUSTER_ID=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')
fi

echo "starting for cluster: $CLUSTER_ID"
echo "backend endpoint: $BACKEND_ENDPOINT"
echo "collectors file: $COLLECTORS_FILE"

send_with_retry() {
  ENDPOINT=$1
  TMPFILE=$2
  MAX_RETRIES=5
  RETRY_COUNT=0

  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -X POST "$ENDPOINT" \
      -H "Content-Type: application/json" \
      -d @"$TMPFILE" \
      --max-time 30 \
      2>/dev/null; then
      rm -f "$TMPFILE"
      return 0
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    WAIT_TIME=$((15 * RETRY_COUNT))
    echo "retry $RETRY_COUNT/$MAX_RETRIES after ${WAIT_TIME}s..."
    sleep $WAIT_TIME
  done

  rm -f "$TMPFILE"
  echo "failed after $MAX_RETRIES retries"
  return 1
}

run_collector() {
  KIND=$1
  COMMAND=$2

  echo "running collector: $KIND"

  OUTPUT=$(bash -c "$COMMAND" 2>/dev/null || true)

  if [ -z "$OUTPUT" ]; then
    echo "collector $KIND produced no output, skipping"
    return 0
  fi

  if ! echo "$OUTPUT" | jq -c --arg cid "$CLUSTER_ID" --arg kind "$KIND" \
      '{cluster_id: $cid, kind: $kind, payload: .}' > /tmp/payload.json 2>/dev/null; then
    echo "collector $KIND produced invalid JSON, skipping"
    return 0
  fi

  send_with_retry "$BACKEND_ENDPOINT/ingest" /tmp/payload.json
}

while true; do
  COLLECTOR_COUNT=$(yq '.collectors | length' "$COLLECTORS_FILE")
  INDEX=0

  while [ "$INDEX" -lt "$COLLECTOR_COUNT" ]; do
    KIND=$(yq ".collectors[$INDEX].kind" "$COLLECTORS_FILE")
    COMMAND=$(yq ".collectors[$INDEX].command" "$COLLECTORS_FILE")

    run_collector "$KIND" "$COMMAND"

    INDEX=$((INDEX + 1))
  done

  echo "sleeping for 60 seconds..."
  sleep 60
done
