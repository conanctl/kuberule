"use client"

import { useQuery } from "@tanstack/react-query"
import { getDerived } from "@/lib/api"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { DataTable } from "@/components/shared/data-table"
import { SeverityPills } from "@/components/shared/severity-pills"
import { ImageEnriched, WorkloadEnriched, NamespaceEnriched, NodeEnriched } from "@/lib/types"
import { ColumnDef } from "@tanstack/react-table"
import { useState } from "react"

export default function AssetsPage() {
  const [clusterId, setClusterId] = useState("default")

  const { data: derived, isLoading } = useQuery({
    queryKey: ["derived", clusterId],
    queryFn: () => getDerived(clusterId),
  })

  if (isLoading) {
    return <div className="text-black">Loading...</div>
  }

  const images = derived?.images || []
  const workloads = derived?.workloads || []
  const namespaces = derived?.namespaces || []
  const nodes = derived?.nodes || []

  const imageColumns: ColumnDef<ImageEnriched>[] = [
    {
      accessorKey: "name",
      header: "Image Name",
    },
    {
      accessorKey: "vulnerabilities",
      header: "Vulnerabilities",
      cell: ({ row }) => {
        return <SeverityPills counts={row.getValue("vulnerabilities")} />
      },
    },
    {
      accessorKey: "used_by",
      header: "Workloads",
      cell: ({ row }) => {
        const workloads = row.getValue("used_by") as string[]
        return <span className="text-black">{workloads.length}</span>
      },
    },
    {
      accessorKey: "nodes",
      header: "Nodes",
      cell: ({ row }) => {
        const nodes = row.getValue("nodes") as string[]
        return <span className="text-black">{nodes.length}</span>
      },
    },
    {
      accessorKey: "status",
      header: "Status",
    },
  ]

  const workloadColumns: ColumnDef<WorkloadEnriched>[] = [
    {
      accessorKey: "name",
      header: "Name",
    },
    {
      accessorKey: "kind",
      header: "Kind",
    },
    {
      accessorKey: "namespace",
      header: "Namespace",
    },
    {
      accessorKey: "pod_count",
      header: "Pods",
    },
    {
      accessorKey: "images",
      header: "Images",
      cell: ({ row }) => {
        const images = row.getValue("images") as string[]
        return <span className="text-black">{images.length}</span>
      },
    },
    {
      accessorKey: "vulnerabilities",
      header: "Vulnerabilities",
      cell: ({ row }) => {
        return <SeverityPills counts={row.getValue("vulnerabilities")} />
      },
    },
  ]

  const namespaceColumns: ColumnDef<NamespaceEnriched>[] = [
    {
      accessorKey: "name",
      header: "Namespace Name",
    },
    {
      accessorKey: "workload_count",
      header: "Workloads",
      cell: ({ row }) => {
        return <span className="text-black">{row.getValue("workload_count")}</span>
      },
    },
    {
      accessorKey: "image_count",
      header: "Images",
      cell: ({ row }) => {
        return <span className="text-black">{row.getValue("image_count")}</span>
      },
    },
    {
      accessorKey: "vulnerabilities",
      header: "Vulnerabilities",
      cell: ({ row }) => {
        return <SeverityPills counts={row.getValue("vulnerabilities")} />
      },
    },
  ]

  const nodeColumns: ColumnDef<NodeEnriched>[] = [
    {
      accessorKey: "name",
      header: "Node Name",
    },
    {
      accessorKey: "used_images",
      header: "Used Images",
      cell: ({ row }) => {
        const images = row.getValue("used_images") as string[]
        return <span className="text-black">{images.length}</span>
      },
    },
    {
      accessorKey: "unused_images",
      header: "Unused Images",
      cell: ({ row }) => {
        const images = row.getValue("unused_images") as string[]
        return <span className="text-black">{images.length}</span>
      },
    },
    {
      accessorKey: "vulnerabilities",
      header: "Vulnerabilities",
      cell: ({ row }) => {
        return <SeverityPills counts={row.getValue("vulnerabilities")} />
      },
    },
  ]

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-black mb-4">Assets</h1>
        <div className="flex items-center gap-4">
          <label className="text-black font-medium">Cluster:</label>
          <select
            value={clusterId}
            onChange={(e) => setClusterId(e.target.value)}
            className="px-4 py-2 border rounded-md text-black"
          >
            <option value="default">default</option>
            <option value="cluster-1">cluster-1</option>
            <option value="cluster-2">cluster-2</option>
          </select>
        </div>
      </div>

      <Tabs defaultValue="images">
        <TabsList>
          <TabsTrigger value="images">Images</TabsTrigger>
          <TabsTrigger value="workloads">Workloads</TabsTrigger>
          <TabsTrigger value="namespaces">Namespaces</TabsTrigger>
          <TabsTrigger value="nodes">Nodes</TabsTrigger>
        </TabsList>

        <TabsContent value="images">
          <DataTable columns={imageColumns} data={images} />
        </TabsContent>

        <TabsContent value="workloads">
          <DataTable columns={workloadColumns} data={workloads} />
        </TabsContent>

        <TabsContent value="namespaces">
          <DataTable columns={namespaceColumns} data={namespaces} />
        </TabsContent>

        <TabsContent value="nodes">
          <DataTable columns={nodeColumns} data={nodes} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
