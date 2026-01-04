import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface MetricCardProps {
  title: string
  value: string | number
  subtitle?: string
}

export function MetricCard({ title, value, subtitle }: MetricCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium text-black">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold text-black">{value}</div>
        {subtitle && (
          <p className="text-sm text-black mt-1">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  )
}
