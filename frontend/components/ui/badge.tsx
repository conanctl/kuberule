import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/types"

export type BadgeVariant = "default" | Severity

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant
}

const variantStyles: Record<BadgeVariant, string> = {
  default: "bg-gray-100 text-gray-800",
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-blue-100 text-blue-800",
}

export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <span
      className={cn("px-2 py-1 rounded-md text-xs font-medium", variantStyles[variant], className)}
      {...props}
    />
  )
}
