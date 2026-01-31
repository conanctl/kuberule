import { cn } from "@/lib/utils"

export function Select({ className, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-black",
        className
      )}
      {...props}
    />
  )
}
