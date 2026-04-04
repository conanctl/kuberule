import type { ReactNode } from "react"

interface QueryBoundaryProps {
  isLoading: boolean
  error?: unknown
  loadingLabel?: string
  errorLabel?: string
  children: ReactNode
}

export function QueryBoundary({
  isLoading,
  error,
  loadingLabel = "Loading...",
  errorLabel = "Error loading data",
  children,
}: QueryBoundaryProps) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">{loadingLabel}</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-600">{errorLabel}</div>
      </div>
    )
  }

  return <>{children}</>
}
