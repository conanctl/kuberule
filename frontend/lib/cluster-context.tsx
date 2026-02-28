"use client"

import { createContext, useContext, useEffect, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { getClusters } from "./api"

type ClusterContextValue = {
  clusters: string[]
  selectedCluster: string
  setSelectedCluster: (cluster: string) => void
  isLoading: boolean
  error: Error | null
}

const ClusterContext = createContext<ClusterContextValue | null>(null)

export function ClusterProvider({ children }: { children: React.ReactNode }) {
  const [selectedCluster, setSelectedCluster] = useState<string>("")

  const { data, isLoading, error } = useQuery({
    queryKey: ["clusters"],
    queryFn: getClusters,
    refetchInterval: 30000,
  })

  const clusters = data?.clusters || []

  useEffect(() => {
    if (selectedCluster === "" && clusters.length > 0) {
      const stored = typeof window !== "undefined" ? window.localStorage.getItem("kuberule-selected-cluster") : null
      if (stored && clusters.includes(stored)) {
        setSelectedCluster(stored)
      } else {
        setSelectedCluster(clusters[0])
      }
    }
  }, [clusters, selectedCluster])

  const updateSelectedCluster = (cluster: string) => {
    setSelectedCluster(cluster)
    if (typeof window !== "undefined") {
      window.localStorage.setItem("kuberule-selected-cluster", cluster)
    }
  }

  return (
    <ClusterContext.Provider
      value={{
        clusters,
        selectedCluster,
        setSelectedCluster: updateSelectedCluster,
        isLoading,
        error: error as Error | null,
      }}
    >
      {children}
    </ClusterContext.Provider>
  )
}

export function useCluster() {
  const ctx = useContext(ClusterContext)
  if (!ctx) {
    throw new Error("useCluster must be used inside ClusterProvider")
  }
  return ctx
}
