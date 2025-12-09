"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Home, AlertTriangle, Shield, Package, CheckCircle } from "lucide-react"

export function Sidebar() {
  const pathname = usePathname()

  const links = [
    { href: "/", label: "Dashboard", icon: Home },
    { href: "/findings", label: "Findings", icon: AlertTriangle },
    { href: "/guardrails", label: "Guardrails", icon: Shield },
    { href: "/assets", label: "Assets", icon: Package },
    { href: "/compliance", label: "Compliance", icon: CheckCircle },
  ]

  return (
    <div className="w-64 bg-gray-900 text-white flex flex-col">
      <div className="p-6">
        <h1 className="text-2xl font-bold">Kuberule</h1>
      </div>

      <nav className="flex-1 px-4">
        {links.map((link) => {
          const Icon = link.icon
          const isActive = pathname === link.href

          return (
            <Link
              key={link.href}
              href={link.href}
              className={`flex items-center gap-3 px-4 py-3 rounded-md mb-2 transition-colors ${
                isActive
                  ? "bg-gray-800 text-white"
                  : "text-gray-400 hover:bg-gray-800 hover:text-white"
              }`}
            >
              <Icon className="w-5 h-5" />
              <span>{link.label}</span>
            </Link>
          )
        })}
      </nav>
    </div>
  )
}
