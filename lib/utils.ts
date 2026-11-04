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
  if (cleanPath.includes("..") || cleanPath.includes("//") || decodeURIComponent(cleanPath).includes("..") || decodeURIComponent(cleanPath).includes("//") || !cleanPath.startsWith("/")) {
    // SECURITY: Use a library like `path.resolve` or `URL` to normalize and validate paths comprehensively.
    return `${env.NEXT_PUBLIC_APP_URL}/`
  }
  const normalizedPath = new URL(cleanPath, env.NEXT_PUBLIC_APP_URL).pathname
  return `${env.NEXT_PUBLIC_APP_URL}${normalizedPath}`
}
