"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { getGuardrails } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { DataTable } from "@/components/shared/data-table"
import { GuardrailPack, GuardrailEntry } from "@/lib/types"
import { ColumnDef } from "@tanstack/react-table"

export default function GuardrailsPage() {
  const queryClient = useQueryClient()

  const { data: packs, isLoading, error } = useQuery({
    queryKey: ["guardrails"],
    queryFn: () => getGuardrails(),
  })

  const reloadMutation = useMutation({
    mutationFn: async () => {
      const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:18081"
      const response = await fetch(`${apiBase}/guardrails/reload`, {
        method: "POST",
      })
      if (!response.ok) throw new Error("Failed to reload")
      return response.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["guardrails"] })
    },
  })

  const evaluateMutation = useMutation({
    mutationFn: async () => {
      const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:18081"
      const response = await fetch(`${apiBase}/guardrails/evaluate?cluster_id=default`)
      if (!response.ok) throw new Error("Failed to evaluate")
      return response.json()
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-black">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-600">Error loading data</div>
      </div>
    )
  }

  const packsList = packs || []

  const allGuardrails: (GuardrailEntry & { packName: string })[] = []

  packsList.forEach((pack: GuardrailPack) => {
    pack.pack.spec.guardrails.forEach((gr: GuardrailEntry) => {
      allGuardrails.push({
        ...gr,
        packName: pack.pack.metadata.name,
      })
    })
  })

  const columns: ColumnDef<GuardrailEntry & { packName: string }>[] = [
    {
      accessorKey: "id",
      header: "ID",
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
      accessorKey: "severity",
      header: "Severity",
      cell: ({ row }) => {
        const severity = row.getValue("severity") as string
        return <Badge variant={severity as any}>{severity}</Badge>
      },
    },
    {
      accessorKey: "target",
      header: "Target Type",
    },
  ]

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-black">Guardrails</h1>
        <div className="flex gap-2">
          <Button
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
          >
            {reloadMutation.isPending ? "Reloading..." : "Reload Packs"}
          </Button>
          <Button
            onClick={() => evaluateMutation.mutate()}
            disabled={evaluateMutation.isPending}
          >
            {evaluateMutation.isPending ? "Evaluating..." : "Evaluate"}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        {packsList.map((pack: GuardrailPack) => (
          <Card key={pack.id}>
            <CardHeader>
              <CardTitle>{pack.pack.metadata.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div>
                  <strong className="text-black">Version:</strong>
                  <span className="text-black ml-2">{pack.pack.metadata.version}</span>
                </div>
                <div>
                  <strong className="text-black">Owner:</strong>
                  <span className="text-black ml-2">{pack.pack.spec.owner}</span>
                </div>
                <div>
                  <strong className="text-black">Guardrails:</strong>
                  <span className="text-black ml-2">{pack.pack.spec.guardrails.length}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Guardrails</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={allGuardrails} />
        </CardContent>
      </Card>
    </div>
  )
}
