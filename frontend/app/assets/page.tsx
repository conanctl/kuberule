"use client"

import { useQuery } from "@tanstack/react-query"
import { getDerived } from "@/lib/api"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { DataTable } from "@/components/shared/data-table"
import { SeverityPills } from "@/components/shared/severity-pills"
import { ImageEnriched, WorkloadEnriched, NamespaceEnriched, NodeEnriched } from "@/lib/types"
import { ColumnDef } from "@tanstack/react-table"
import { useCluster } from "@/lib/cluster-context"
import { QueryBoundary } from "@/components/shared/query-boundary"

export default function AssetsPage() {
  const { selectedCluster } = useCluster()

  const { data: derived, isLoading, error } = useQuery({
    queryKey: ["derived", selectedCluster],
    queryFn: () => getDerived(selectedCluster),
    enabled: selectedCluster !== "",
  })

  if (isLoading || error) {
    return <QueryBoundary isLoading={isLoading} error={error}>{null}</QueryBoundary>
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
        return <span className="">{workloads.length}</span>
      },
    },
    {
      accessorKey: "nodes",
      header: "Nodes",
      cell: ({ row }) => {
        const nodes = row.getValue("nodes") as string[]
        return <span className="">{nodes.length}</span>
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
        return <span className="">{images.length}</span>
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
      header: "Name",
    },
    {
      accessorKey: "workload_count",
      header: "Workloads",
    },
    {
      accessorKey: "image_count",
      header: "Images",
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
      header: "Name",
    },
    {
      accessorKey: "used_images",
      header: "Used Images",
      cell: ({ row }) => {
        const images = row.getValue("used_images") as string[]
        return <span className="">{images.length}</span>
      },
    },
    {
      accessorKey: "unused_images",
      header: "Unused Images",
      cell: ({ row }) => {
        const images = row.getValue("unused_images") as string[]
        return <span className="">{images.length}</span>
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
        <h1 className="text-3xl font-bold mb-4">Assets</h1>
        <p className="text-sm text-gray-600">Showing data for cluster: <span className="font-mono">{selectedCluster || "none"}</span></p>
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
