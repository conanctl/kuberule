"use client"

import { useQuery } from "@tanstack/react-query"
import { getFindings } from "@/lib/api"
import { MetricCard } from "@/components/shared/metric-card"
import { Finding } from "@/lib/types"

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

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8 text-gray-900">Command Center</h1>

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
    </div>
  )
}
