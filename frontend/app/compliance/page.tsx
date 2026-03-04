"use client"

import { useQuery } from "@tanstack/react-query"
import { getMetrics, getMetricsHistory } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { MetricCard } from "@/components/shared/metric-card"
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts"
import { useCluster } from "@/lib/cluster-context"

export default function CompliancePage() {
  const { selectedCluster } = useCluster()

  const metricsQuery = useQuery({
    queryKey: ["metrics", selectedCluster],
    queryFn: () => getMetrics(selectedCluster),
  })

  const historyQuery = useQuery({
    queryKey: ["metrics-history", selectedCluster],
    queryFn: () => getMetricsHistory(selectedCluster, 50),
    enabled: selectedCluster !== "",
  })

  if (metricsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-black">Loading...</div>
      </div>
    )
  }

  if (metricsQuery.error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-600">Error loading data</div>
      </div>
    )
  }

  const metrics = metricsQuery.data

  const compliancePct = metrics?.compliance_pct ?? 0
  const activeGuardrails = metrics?.active_guardrails ?? 0
  const openFindings = metrics?.open_findings ?? 0

  const byCategory: Record<string, number> = metrics?.by_category ?? {}
  const categoryData = Object.keys(byCategory).map((categoryName) => {
    return {
      category: categoryName,
      open: byCategory[categoryName],
    }
  })

  const severityData = [
    { name: "Critical", count: metrics?.by_severity?.critical ?? 0 },
    { name: "High", count: metrics?.by_severity?.high ?? 0 },
    { name: "Medium", count: metrics?.by_severity?.medium ?? 0 },
    { name: "Low", count: metrics?.by_severity?.low ?? 0 },
  ]

  type OwnerEntry = {
    owner: string
    critical: number
    high: number
    medium: number
    low: number
    total: number
  }

  const byOwner: OwnerEntry[] = metrics?.by_owner ?? []

  const teamLeaderboard = [...byOwner]
    .map((entry) => ({
      team: entry.owner === "" ? "unassigned" : entry.owner,
      critical: entry.critical,
      high: entry.high,
      medium: entry.medium,
      low: entry.low,
      total: entry.total,
    }))
    .sort((a, b) => b.total - a.total)

  type HistoryEntry = {
    ran_at: string
    health_score: number
    compliance_pct: number
    open_findings: number
    resolved_findings: number
  }

  const historyEntries: HistoryEntry[] = historyQuery.data?.history ?? []
  const trendData = historyEntries.map((entry) => {
    const timestamp = new Date(entry.ran_at)
    return {
      label: timestamp.toLocaleString(),
      health_score: entry.health_score,
      compliance_pct: Math.round(entry.compliance_pct * 10) / 10,
    }
  })

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8 text-black">Compliance</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <MetricCard
          title="Compliance Score"
          value={`${compliancePct.toFixed(1)}%`}
          subtitle="Resolved / total findings"
        />
        <MetricCard
          title="Active Guardrails"
          value={activeGuardrails}
          subtitle="Loaded policies"
        />
        <MetricCard
          title="Open Findings"
          value={openFindings}
          subtitle="Requiring attention"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle>Open Findings by Category</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryData}>
                <XAxis dataKey="category" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="open" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Open Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <Card className="mb-8">
        <CardHeader>
          <CardTitle>Compliance Trend (last 50 evaluations)</CardTitle>
        </CardHeader>
        <CardContent>
          {trendData.length < 2 ? (
            <div className="text-sm text-gray-500 py-8 text-center">
              Not enough evaluations yet — run Evaluate at least twice to see a trend.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={trendData}>
                <XAxis dataKey="label" tick={{ fontSize: 10 }} />
                <YAxis yAxisId="left" domain={[0, 100]} />
                <YAxis yAxisId="right" orientation="right" domain={[0, 100]} />
                <Tooltip />
                <Legend />
                <Line yAxisId="left" type="monotone" dataKey="health_score" stroke="#3b82f6" name="Health Score" dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="compliance_pct" stroke="#10b981" name="Compliance %" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Team Leaderboard</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 text-black">Team</th>
                <th className="text-right py-2 text-black">Critical</th>
                <th className="text-right py-2 text-black">High</th>
                <th className="text-right py-2 text-black">Medium</th>
                <th className="text-right py-2 text-black">Low</th>
                <th className="text-right py-2 text-black">Total</th>
              </tr>
            </thead>
            <tbody>
              {teamLeaderboard.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-center text-gray-500">
                    No open findings yet.
                  </td>
                </tr>
              )}
              {teamLeaderboard.map((team) => (
                <tr key={team.team} className="border-b">
                  <td className="py-2 text-black">{team.team}</td>
                  <td className="text-right text-black">{team.critical}</td>
                  <td className="text-right text-black">{team.high}</td>
                  <td className="text-right text-black">{team.medium}</td>
                  <td className="text-right text-black">{team.low}</td>
                  <td className="text-right font-bold text-black">{team.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
