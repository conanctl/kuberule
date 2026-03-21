"use client"

import { useQuery } from "@tanstack/react-query"
import { getFindings, getMetrics } from "@/lib/api"
import { MetricCard } from "@/components/shared/metric-card"
import { Finding, toSeverity } from "@/lib/types"
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useCluster } from "@/lib/cluster-context"

export default function Dashboard() {
  const { selectedCluster } = useCluster()

  const metricsQuery = useQuery({
    queryKey: ["metrics", selectedCluster],
    queryFn: () => getMetrics(selectedCluster),
  })

  const aggregateMetricsQuery = useQuery({
    queryKey: ["metrics", "aggregate"],
    queryFn: () => getMetrics(""),
  })

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedCluster],
    queryFn: () => {
      const filters: Record<string, string> = {}
      if (selectedCluster !== "") {
        filters.cluster_id = selectedCluster
      }
      return getFindings(filters)
    },
  })

  if (metricsQuery.isLoading || findingsQuery.isLoading || aggregateMetricsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading...</div>
      </div>
    )
  }

  if (metricsQuery.error || findingsQuery.error || aggregateMetricsQuery.error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-600">Error loading data</div>
      </div>
    )
  }

  const metrics = metricsQuery.data
  const aggregateMetrics = aggregateMetricsQuery.data
  const findingsList = findingsQuery.data || []

  const healthScore = metrics?.health_score ?? 0
  const openFindings = metrics?.open_findings ?? 0
  const criticalCount = metrics?.by_severity?.critical ?? 0
  const totalVulns =
    (metrics?.by_severity?.critical ?? 0) +
    (metrics?.by_severity?.high ?? 0) +
    (metrics?.by_severity?.medium ?? 0) +
    (metrics?.by_severity?.low ?? 0)

  const byCategoryMap: Record<string, number> = metrics?.by_category ?? {}
  const categoryData = Object.keys(byCategoryMap).map((categoryName) => {
    return {
      name: categoryName,
      total: byCategoryMap[categoryName],
    }
  })

  const severityData = [
    { name: "Critical", count: metrics?.by_severity?.critical ?? 0 },
    { name: "High", count: metrics?.by_severity?.high ?? 0 },
    { name: "Medium", count: metrics?.by_severity?.medium ?? 0 },
    { name: "Low", count: metrics?.by_severity?.low ?? 0 },
  ]

  const perCluster: { cluster_id: string; risk_score: number; open: number; health_score: number }[] =
    aggregateMetrics?.per_cluster ?? []
  const topClusters = [...perCluster]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5)

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Command Center</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          title="Health Score"
          value={healthScore}
          subtitle="Overall security posture"
        />
        <MetricCard
          title="Active Findings"
          value={openFindings}
          subtitle="Open issues"
        />
        <MetricCard
          title="Critical Findings"
          value={criticalCount}
          subtitle="Immediate attention required"
        />
        <MetricCard
          title="Total Vulnerabilities"
          value={totalVulns}
          subtitle={selectedCluster === "" ? "Across all clusters" : `In cluster ${selectedCluster}`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle>Findings by Category</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryData} layout="vertical">
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={140} />
                <Tooltip />
                <Legend />
                <Bar dataKey="total" fill="#3b82f6" name="Open findings" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top 5 Riskiest Clusters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {topClusters.length === 0 && (
              <div className="text-sm text-gray-500">No clusters with open findings.</div>
            )}
            {topClusters.map((cluster) => (
              <div key={cluster.cluster_id} className="flex justify-between items-center p-3 bg-gray-50 rounded">
                <span className="font-medium">{cluster.cluster_id}</span>
                <span className="text-red-600 font-bold">Risk: {cluster.risk_score.toFixed(1)}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Recent Critical & High Findings</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2">Severity</th>
                <th className="text-left py-2">Title</th>
                <th className="text-left py-2">Target</th>
                <th className="text-left py-2">Cluster</th>
                <th className="text-left py-2">First Seen</th>
              </tr>
            </thead>
            <tbody>
              {findingsList
                .filter((f: Finding) => f.severity === "critical" || f.severity === "high")
                .slice(0, 10)
                .map((finding: Finding) => (
                  <tr key={finding.id} className="border-b">
                    <td className="py-2">
                      <Badge variant={toSeverity(finding.severity) ?? "default"}>{finding.severity}</Badge>
                    </td>
                    <td className="py-2">{finding.title}</td>
                    <td className="py-2">{finding.target_identifier}</td>
                    <td className="py-2">{finding.cluster_id}</td>
                    <td className="py-2">{new Date(finding.first_seen_at).toLocaleDateString()}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
