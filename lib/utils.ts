import { ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

import { env } from "@/env.mjs"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(input: string | number): string {
  const date = new Date(input)
  return date.toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  })
}

export function absoluteUrl(path: string) {
  const cleanPath = path.startsWith("/") ? path : `/${path}`
  if (cleanPath.includes("..") || cleanPath.includes("//") || decodeURIComponent(cleanPath).includes("..") || decodeURIComponent(cleanPath).includes("//")) {
    return `${env.NEXT_PUBLIC_APP_URL}/`
  }
  return `${env.NEXT_PUBLIC_APP_URL}${cleanPath}`
}
