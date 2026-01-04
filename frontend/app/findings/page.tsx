"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { getFindings, updateFindingStatus } from "@/lib/api"
import { DataTable } from "@/components/shared/data-table"
import { Badge } from "@/components/ui/badge"
import { Finding } from "@/lib/types"
import { ColumnDef } from "@tanstack/react-table"
import { useState } from "react"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const queryClient = useQueryClient()

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => getFindings(),
  })

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      updateFindingStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] })
      setSelectedFinding(null)
    },
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
      cell: ({ row }) => {
        const finding = row.original
        return (
          <button
            onClick={() => setSelectedFinding(finding)}
            className="text-blue-600 hover:text-blue-800 underline cursor-pointer"
          >
            {row.getValue("title")}
          </button>
        )
      },
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

      <Tabs defaultValue="all">
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="urgent">Urgent</TabsTrigger>
          <TabsTrigger value="open">Open</TabsTrigger>
          <TabsTrigger value="acknowledged">Acknowledged</TabsTrigger>
          <TabsTrigger value="resolved">Resolved</TabsTrigger>
        </TabsList>

        <TabsContent value="all">
          <DataTable columns={columns} data={findingsList} />
        </TabsContent>

        <TabsContent value="urgent">
          <DataTable
            columns={columns}
            data={findingsList.filter((f: Finding) => f.severity === "critical" || f.severity === "high")}
          />
        </TabsContent>

        <TabsContent value="open">
          <DataTable
            columns={columns}
            data={findingsList.filter((f: Finding) => f.status === "open")}
          />
        </TabsContent>

        <TabsContent value="acknowledged">
          <DataTable
            columns={columns}
            data={findingsList.filter((f: Finding) => f.status === "acknowledged")}
          />
        </TabsContent>

        <TabsContent value="resolved">
          <DataTable
            columns={columns}
            data={findingsList.filter((f: Finding) => f.status === "resolved")}
          />
        </TabsContent>
      </Tabs>

      {selectedFinding && (
        <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{selectedFinding.title}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <strong className="text-black">Guardrail ID:</strong>
                <span className="text-black ml-2">{selectedFinding.guardrail_id}</span>
              </div>
              <div>
                <strong className="text-black">Severity:</strong>
                <span className="ml-2">
                  <Badge variant={selectedFinding.severity as any}>{selectedFinding.severity}</Badge>
                </span>
              </div>
              <div>
                <strong className="text-black">Category:</strong>
                <span className="text-black ml-2">{selectedFinding.category}</span>
              </div>
              <div>
                <strong className="text-black">Target:</strong>
                <span className="text-black ml-2">{selectedFinding.target_type} / {selectedFinding.target_identifier}</span>
              </div>
              <div>
                <strong className="text-black">Cluster:</strong>
                <span className="text-black ml-2">{selectedFinding.cluster_id}</span>
              </div>
              <div>
                <strong className="text-black">Namespace:</strong>
                <span className="text-black ml-2">{selectedFinding.namespace}</span>
              </div>
              <div>
                <strong className="text-black">Current Status:</strong>
                <span className="text-black ml-2">{selectedFinding.status}</span>
              </div>
              <div>
                <strong className="text-black">Remediation:</strong>
                <span className="text-black ml-2">{selectedFinding.remediation_hint}</span>
              </div>
              <div className="flex gap-2 pt-4">
                <Button
                  onClick={() => updateStatusMutation.mutate({ id: selectedFinding.id, status: "acknowledged" })}
                  disabled={updateStatusMutation.isPending}
                >
                  {updateStatusMutation.isPending ? "Updating..." : "Acknowledge"}
                </Button>
                <Button
                  onClick={() => updateStatusMutation.mutate({ id: selectedFinding.id, status: "resolved" })}
                  disabled={updateStatusMutation.isPending}
                >
                  {updateStatusMutation.isPending ? "Updating..." : "Resolve"}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
