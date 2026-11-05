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

    function userCanAccessBillingPortal(user: any): boolean {
      return Boolean(user?.id && user?.email)
    }

    // SECURITY: add a check that the authenticated caller has access to the billing portal; this repo's specific authorization API was not visible in this snippet.
    if (!session?.user || !session?.user.email || !userCanAccessBillingPortal(session.user)) {
      return new Response("Unauthorized", { status: 403 })
    }

    // SECURITY: Add an authorization check here ensuring the caller is authenticated and authorized to access this endpoint before validating the origin header.
    if (!session?.user?.id) {
      return new Response("Unauthorized", { status: 403 })
    }
    const origin = req.headers.get("origin")
    if (origin) {
      const allowedOrigin = new URL(env.NEXT_PUBLIC_APP_URL).origin
      if (origin !== allowedOrigin) {
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
      // SECURITY: add an authorization check here verifying the caller may access resource <session.user.id> before this line runs - this codebase's auth/permission-check API was not visible in the analysed snippet
      if (!session?.user?.id || !userCanAccessBillingPortal(session.user)) {
        return new Response("Unauthorized", { status: 403 })
      }

      const stripeSession = await stripe.billingPortal.sessions.create({
        customer: subscriptionPlan.stripeCustomerId,
        return_url: billingUrl,
      })

      const sanitizedUrl = encodeURIComponent(stripeSession.url)
      return new Response(JSON.stringify({ url: sanitizedUrl }))
    }

    // The user is on the free plan.
    // Create a checkout session to upgrade.
    // SECURITY: add an authorization check here verifying the caller may access resource <session.user.id> before this line runs - this codebase's auth/permission-check API was not visible in the analysed snippet
    if (!session?.user?.id || !userCanAccessBillingPortal(session.user)) {
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
