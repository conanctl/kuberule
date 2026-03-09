# KubeRule

A declarative, policy-driven management engine for Kubernetes clusters. KubeRule continuously scans your clusters for security vulnerabilities, evaluates them against configurable guardrail policies, and surfaces findings through a web dashboard.

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- [Helm](https://helm.sh/docs/intro/install/)
- A running Kubernetes cluster (e.g. [minikube](https://minikube.sigs.k8s.io/docs/start/), [kind](https://kind.sigs.k8s.io/), or a cloud provider)

### Step 1 — Start the platform

```bash
git clone https://github.com/conanctl/university-project-kuberule.git
cd university-project-kuberule
docker compose up -d
```

This pulls pre-built images and starts the backend, frontend, and database. The schema is created automatically and the bundled guardrail packs are loaded on startup.

| Service   | URL                   |
| --------- | --------------------- |
| Dashboard | http://localhost:3000  |
| API       | http://localhost:18081 |

### Step 2 — Deploy the agent to your cluster

```bash
helm install kuberule-agent ./helm/kuberule-agent \
  --set backend.endpoint=http://<YOUR_MACHINE_IP>:18081
```

Replace `<YOUR_MACHINE_IP>` with the IP of the machine running docker compose:
- **Linux:** `hostname -I | awk '{print $1}'`
- **macOS:** `ipconfig getifaddr en0`
- **minikube:** `minikube ssh -- route -n | grep ^0.0.0.0 | awk '{print $2}'`

The agent image is pulled automatically from the container registry. It will begin collecting cluster state every 60 seconds. Verify it's running:

```bash
kubectl logs -l app=kuberule-agent -f
```

### Step 3 — View results

1. Open http://localhost:3000
2. Go to **Guardrails** and click **Evaluate**
3. Check **Findings** for policy violations
4. Browse **Assets** to see your cluster's images, workloads, and nodes

### Connecting additional clusters

Each cluster only needs its own agent. Install with a different release name:

```bash
helm install kuberule-agent-staging ./helm/kuberule-agent \
  --set backend.endpoint=http://<YOUR_MACHINE_IP>:18081
```

All clusters appear in the same dashboard automatically.

## Configuration

### Environment Variables

| Variable              | Component | Default                                              | Description                    |
| --------------------- | --------- | ---------------------------------------------------- | ------------------------------ |
| `DATABASE_URL`        | Backend   | `postgres://user:pass@localhost/kuberule?sslmode=disable` | PostgreSQL connection string   |
| `PORT`                | Backend   | `18081`                                              | Backend server port            |
| `GUARDRAILS_DIR`      | Backend   | `backend/guardrails/packs`                           | Path to guardrail pack files   |
| `NEXT_PUBLIC_API_BASE`| Frontend  | `http://localhost:18081`                             | Backend API URL                |
| `BACKEND_ENDPOINT`    | Agent     | `http://localhost:18081`                             | Backend API URL for agent      |
| `CLUSTER_ID`          | Agent     | Auto-discovered from kube-system namespace UID       | Cluster identifier             |

### Guardrail Packs

Guardrail packs define the policies that KubeRule evaluates. Two packs ship out of the box:

- **baseline-standards** — Image vulnerability thresholds, required namespace labels, unused image detection
- **pod-security-standards** — Resource limits, privilege restrictions, health check enforcement

Add your own by dropping a `.yaml` (or `.json`) file into `backend/guardrails/packs/` and clicking **Reload Packs** in the dashboard. A minimal pack looks like:

```yaml
apiVersion: kuberule.io/v1
kind: GuardrailPack
metadata:
  name: my-pack
  version: 0.1.0
spec:
  description: My custom guardrails
  owner: my-team
  scope:
    clusters: ["*"]
  guardrails:
    - id: MY-001
      title: Namespaces must have owner label
      category: compliance
      severity: medium
      target: namespace
      check:
        type: required_label
        params:
          labelKey: owner
      remediationHint: Add an `owner` label to the namespace
      rationale: Ownership is required for paging
      exceptions: []
```

## Development Setup (without Docker)

### Prerequisites

- [Go](https://go.dev/dl/) 1.22+
- [Node.js](https://nodejs.org/) 20+
- [PostgreSQL](https://www.postgresql.org/download/) 14+

```bash
# Create the database and start the backend
createdb kuberule
cd backend
export DATABASE_URL="postgres://localhost/kuberule?sslmode=disable"
go run main.go

# In another terminal, start the frontend
cd frontend
npm install
npm run dev
```

## API Reference

| Method | Endpoint                | Description                           |
| ------ | ----------------------- | ------------------------------------- |
| GET    | `/health`               | Health check                          |
| POST   | `/ingest`               | Ingest cluster snapshot from agent    |
| GET    | `/guardrails`           | List loaded guardrail packs           |
| POST   | `/guardrails/reload`    | Reload guardrail packs from disk      |
| GET    | `/guardrails/evaluate`  | Evaluate guardrails for a cluster     |
| GET    | `/findings`             | List findings (filterable)            |
| POST   | `/findings`             | Update finding status                 |
| GET    | `/debug/derived`        | Get enriched cluster model            |
| GET    | `/debug/raw`            | Get raw snapshots                     |

## Tech Stack

- **Backend**: Go, PostgreSQL
- **Frontend**: Next.js, React, Tailwind CSS, Recharts
- **Agent**: Shell script with kubectl and Trivy
- **Deployment**: Docker Compose (platform), Helm (agent)
