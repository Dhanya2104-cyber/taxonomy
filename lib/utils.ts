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
  if (!env.NEXT_PUBLIC_APP_URL.startsWith('https://')) {
    throw new Error('Invalid base URL');
  }
  const sanitizedPath = path.replace(/[^a-zA-Z0-9/_-]/g, '').replace(/\.\./g, '');
  if (sanitizedPath.includes('..')) {
    throw new Error('Path traversal detected');
  }
  const normalizedPath = new URL(sanitizedPath.startsWith('/') ? sanitizedPath : `/${sanitizedPath}`, env.NEXT_PUBLIC_APP_URL).pathname;
  return `${env.NEXT_PUBLIC_APP_URL}${normalizedPath}`;
}
