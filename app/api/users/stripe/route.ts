import { getServerSession } from "next-auth/next"
import { z } from "zod"

import { proPlan } from "@/config/subscriptions"
import { authOptions } from "@/lib/auth"
import { stripe } from "@/lib/stripe"
import { getUserSubscriptionPlan } from "@/lib/subscription"
import { absoluteUrl } from "@/lib/utils"
import { env } from "@/env.mjs"

const billingUrl = absoluteUrl("/dashboard/billing")

function userCanAccessBillingPortal(user: any): boolean {
  return Boolean(user?.id && user?.email)
}

export async function GET(req: Request) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user || !session?.user.email) {
      return new Response(null, { status: 403 })
    }

    // SECURITY: Use a stricter validation mechanism for the origin header that accounts for subdomains and variations in the URL structure.
    const origin = req.headers.get("origin")
    if (origin) {
      const allowedOrigin = new URL(env.NEXT_PUBLIC_APP_URL).origin
      if (!origin.endsWith(allowedOrigin)) {
        return new Response("Invalid origin", { status: 403 })
      }
    }

    const csrfToken = req.headers.get("x-csrf-token")
    if (req.method === "POST" && !csrfToken) {
      return new Response("Invalid CSRF token", { status: 403 })
    }

    const subscriptionPlan = await getUserSubscriptionPlan(session.user.id)

    if (!session?.user?.id || !subscriptionPlan) {
      return new Response("Unauthorized", { status: 403 })
    }

    // The user is on the pro plan.
    // Create a portal session to manage subscription.
    if (subscriptionPlan.isPro && subscriptionPlan.stripeCustomerId) {
      if (!userCanAccessBillingPortal(session.user)) {
        return new Response("Unauthorized", { status: 403 })
      }

      const stripeSession = await stripe.billingPortal.sessions.create({
        customer: subscriptionPlan.stripeCustomerId,
        return_url: billingUrl,
      })

      const sanitizedUrl = encodeURI(stripeSession.url)
      return new Response(JSON.stringify({ url: sanitizedUrl }))
    }

    // The user is on the free plan.
    // Create a checkout session to upgrade.
    if (!userCanAccessBillingPortal(session.user)) {
      return new Response("Unauthorized", { status: 403 })
    }

    const stripeSession = await stripe.checkout.sessions.create({
      success_url: billingUrl,
      cancel_url: billingUrl,
      payment_method_types: ["card"],
      mode: "subscription",
      billing_address_collection: "auto",
      customer_email: session.user.email,
      line_items: [
        {
          price: proPlan.stripePriceId,
          quantity: 1,
        },
      ],
      metadata: {
        userId: session.user.id,
      },
    })

    const sanitizedUrl = encodeURI(stripeSession.url)
    return new Response(JSON.stringify({ url: sanitizedUrl }))
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify(error.issues), { status: 422 })
    }

    return new Response(null, { status: 500 })
  }
}
