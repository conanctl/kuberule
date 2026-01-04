"use client"

import { useQuery } from "@tanstack/react-query"
import { getFindings } from "@/lib/api"
import { MetricCard } from "@/components/shared/metric-card"
import { Finding } from "@/lib/types"
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function Dashboard() {
  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => getFindings(),
  })

  if (isLoading) {
    return <div>Loading...</div>
  }

  const findingsList = findings || []

  const criticalCount = findingsList.filter((f: Finding) => f.severity === "critical").length
  const highCount = findingsList.filter((f: Finding) => f.severity === "high").length
  const mediumCount = findingsList.filter((f: Finding) => f.severity === "medium").length
  const lowCount = findingsList.filter((f: Finding) => f.severity === "low").length

  const healthScore = Math.max(0, 100 - (criticalCount * 10 + highCount * 5 + mediumCount * 1))

  const activeFindings = findingsList.filter((f: Finding) => f.status === "open").length

  const totalVulns = criticalCount + highCount + mediumCount + lowCount

  const categoryData = [
    { name: "Security", value: findingsList.filter((f: Finding) => f.category === "Security").length },
    { name: "Compliance", value: findingsList.filter((f: Finding) => f.category === "Compliance").length },
    { name: "Hygiene", value: findingsList.filter((f: Finding) => f.category === "Hygiene").length },
    { name: "Observability", value: findingsList.filter((f: Finding) => f.category === "Observability").length },
  ]

  const severityData = [
    { name: "Critical", count: criticalCount },
    { name: "High", count: highCount },
    { name: "Medium", count: mediumCount },
    { name: "Low", count: lowCount },
  ]

  const clusterMap: Record<string, number> = {}
  findingsList.forEach((f: Finding) => {
    const clusterId = f.cluster_id
    if (!clusterMap[clusterId]) {
      clusterMap[clusterId] = 0
    }
    clusterMap[clusterId] += f.severity === "critical" ? 4 : f.severity === "high" ? 2 : f.severity === "medium" ? 1 : 0.5
  })

  const topClusters = Object.entries(clusterMap)
    .map(([cluster, risk]) => ({ cluster, risk }))
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 5)

  const COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6"]

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8 text-black">Command Center</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          title="Health Score"
          value={healthScore}
          subtitle="Overall security posture"
        />
        <MetricCard
          title="Active Findings"
          value={activeFindings}
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
          subtitle="Across all clusters"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle>Findings by Category</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={categoryData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry) => entry.name}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {categoryData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
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
                <YAxis />
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
            {topClusters.map((cluster) => (
              <div key={cluster.cluster} className="flex justify-between items-center p-3 bg-gray-50 rounded">
                <span className="font-medium text-black">{cluster.cluster}</span>
                <span className="text-red-600 font-bold">Risk: {cluster.risk.toFixed(1)}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
