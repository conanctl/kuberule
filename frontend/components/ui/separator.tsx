import { cn } from "@/lib/utils"

export function Separator({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("h-px bg-gray-200", className)} {...props} />
}
