import Stripe from "stripe"

import { env } from "@/env.mjs"

const secretsManager = {
  get: (key: string) => process.env[key] || "",
}

// SECURITY: integrate a dedicated secrets manager or vault API to securely retrieve the STRIPE_API_KEY.
export const stripe = new Stripe(secretsManager.get("STRIPE_API_KEY") {
  apiVersion: "2022-11-15",
  typescript: true,
})
