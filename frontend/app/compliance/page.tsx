"use client"

import { useQuery } from "@tanstack/react-query"
import { getFindings, getGuardrails } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { MetricCard } from "@/components/shared/metric-card"
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"
import { Finding, GuardrailPack } from "@/lib/types"

export default function CompliancePage() {
  const { data: findings, isLoading: findingsLoading, error: findingsError } = useQuery({
    queryKey: ["findings"],
    queryFn: () => getFindings(),
  })

  const { data: packs, isLoading: packsLoading, error: packsError } = useQuery({
    queryKey: ["guardrails"],
    queryFn: () => getGuardrails(),
  })

  const isLoading = findingsLoading || packsLoading
  const error = findingsError || packsError

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

  const findingsList = findings || []
  const packsList = packs || []

  const totalGuardrails = packsList.reduce((sum: number, pack: GuardrailPack) => {
    return sum + pack.pack.spec.guardrails.length
  }, 0)

  const resolvedFindings = findingsList.filter((f: Finding) => f.status === "resolved").length
  const totalFindings = findingsList.length

  const complianceScore = totalFindings > 0 ? Math.round((resolvedFindings / totalFindings) * 100) : 100

  const categories = ["Security", "Resource Management", "Image Security", "Network Security"]
  const categoryCompliance = categories.map((cat) => {
    const catFindings = findingsList.filter((f: Finding) => f.category === cat)
    const catResolved = catFindings.filter((f: Finding) => f.status === "resolved").length
    const percentage = catFindings.length > 0 ? Math.round((catResolved / catFindings.length) * 100) : 100
    return { category: cat, resolved: percentage }
  })

  const severityData = [
    { name: "Critical", count: findingsList.filter((f: Finding) => f.severity === "critical" && f.status === "open").length },
    { name: "High", count: findingsList.filter((f: Finding) => f.severity === "high" && f.status === "open").length },
    { name: "Medium", count: findingsList.filter((f: Finding) => f.severity === "medium" && f.status === "open").length },
    { name: "Low", count: findingsList.filter((f: Finding) => f.severity === "low" && f.status === "open").length },
  ]

  const teamMap: Record<string, { critical: number; high: number; medium: number; low: number }> = {}

  findingsList.forEach((f: Finding) => {
    const team = f.owner_label_value || "unassigned"
    if (!teamMap[team]) {
      teamMap[team] = { critical: 0, high: 0, medium: 0, low: 0 }
    }
    if (f.severity === "critical") teamMap[team].critical++
    else if (f.severity === "high") teamMap[team].high++
    else if (f.severity === "medium") teamMap[team].medium++
    else if (f.severity === "low") teamMap[team].low++
  })

  const teamLeaderboard = Object.entries(teamMap).map(([team, counts]) => ({
    team,
    ...counts,
    total: counts.critical + counts.high + counts.medium + counts.low,
  })).sort((a, b) => b.total - a.total)

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8 text-black">Compliance</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <MetricCard
          title="Compliance Score"
          value={`${complianceScore}%`}
          subtitle="Resolved findings"
        />
        <MetricCard
          title="Total Guardrails"
          value={totalGuardrails}
          subtitle="Active policies"
        />
        <MetricCard
          title="Open Findings"
          value={findingsList.filter((f: Finding) => f.status === "open").length}
          subtitle="Requiring attention"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle>Category Compliance</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryCompliance}>
                <XAxis dataKey="category" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="resolved" fill="#10b981" />
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
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

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
