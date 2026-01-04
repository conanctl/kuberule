"use client"

import { useQuery } from "@tanstack/react-query"
import { getFindings } from "@/lib/api"
import { DataTable } from "@/components/shared/data-table"
import { Badge } from "@/components/ui/badge"
import { Finding } from "@/lib/types"
import { ColumnDef } from "@tanstack/react-table"
import { useState } from "react"

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [statusFilter, setStatusFilter] = useState<string>("all")

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => getFindings(),
  })

  if (isLoading) {
    return <div>Loading...</div>
  }

  let findingsList = findings || []

  if (severityFilter !== "all") {
    findingsList = findingsList.filter((f: Finding) => f.severity === severityFilter)
  }

  if (statusFilter !== "all") {
    findingsList = findingsList.filter((f: Finding) => f.status === statusFilter)
  }

  const columns: ColumnDef<Finding>[] = [
    {
      accessorKey: "severity",
      header: "Severity",
      cell: ({ row }) => {
        const severity = row.getValue("severity") as string
        return <Badge variant={severity as any}>{severity.toUpperCase()}</Badge>
      },
    },
    {
      accessorKey: "title",
      header: "Title",
    },
    {
      accessorKey: "category",
      header: "Category",
    },
    {
      accessorKey: "guardrail_id",
      header: "Guardrail ID",
    },
    {
      accessorKey: "cluster_id",
      header: "Cluster",
    },
    {
      accessorKey: "target_type",
      header: "Target Type",
    },
    {
      accessorKey: "target_identifier",
      header: "Target",
    },
    {
      accessorKey: "namespace",
      header: "Namespace",
    },
    {
      accessorKey: "status",
      header: "Status",
    },
  ]

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8 text-black">Findings</h1>

      <div className="flex gap-4 mb-6">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-4 py-2 border rounded-md text-black"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-4 py-2 border rounded-md text-black"
        >
          <option value="all">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      <DataTable columns={columns} data={findingsList} />
    </div>
  )
}
