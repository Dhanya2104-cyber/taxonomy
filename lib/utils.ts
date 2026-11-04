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
  // SECURITY: consider using a library like `path.resolve` to normalize and validate paths comprehensively.
  if (cleanPath.includes("..") || cleanPath.includes("//") || decodeURIComponent(cleanPath).includes("..") || decodeURIComponent(cleanPath).includes("//") || !cleanPath.startsWith("/")) {
    return `${env.NEXT_PUBLIC_APP_URL}/`
  }
  return `${env.NEXT_PUBLIC_APP_URL}${cleanPath}`
}
