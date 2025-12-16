import { Badge } from "@/components/ui/badge"
import { SeverityCounts } from "@/lib/types"

interface SeverityPillsProps {
  counts: SeverityCounts
}

export function SeverityPills({ counts }: SeverityPillsProps) {
  return (
    <div className="flex gap-2">
      {counts.critical > 0 && (
        <Badge variant="critical">
          Critical: {counts.critical}
        </Badge>
      )}
      {counts.high > 0 && (
        <Badge variant="high">
          High: {counts.high}
        </Badge>
      )}
      {counts.medium > 0 && (
        <Badge variant="medium">
          Medium: {counts.medium}
        </Badge>
      )}
      {counts.low > 0 && (
        <Badge variant="low">
          Low: {counts.low}
        </Badge>
      )}
    </div>
  )
}
