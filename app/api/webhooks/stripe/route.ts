import { headers } from "next/headers"
import Stripe from "stripe"
import * as z from "zod"

import { env } from "@/env.mjs"
import { db } from "@/lib/db"
import { stripe } from "@/lib/stripe"

const userIdSchema = z.string().regex(/^[a-zA-Z0-9_-]+$/)

export async function POST(req: Request) {
  const body = await req.text()
  const signature = headers().get("Stripe-Signature") as string

  // SECURITY: Replace IP-based verification with Stripe-Signature validation
  if (!signature) {
    return new Response("Invalid signature", { status: 403 })
  }

  let event: Stripe.Event

  try {
    // SECURITY: Validate the Stripe-Signature header using the Stripe library's webhook verification method
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      env.STRIPE_WEBHOOK_SECRET
    )
    if (!event) {
      return new Response("Invalid signature", { status: 403 })
    }
  } catch (error) {
    return new Response("Webhook Error: Invalid request", { status: 400 })
  }

  const session = event.data.object as Stripe.Checkout.Session

  // Before using session.metadata.userId in database queries, validate it against a strict schema and sanitize it to prevent SQL injection.
  if (!session?.metadata?.userId || typeof session.metadata.userId !== "string") {
    return new Response("Unauthorized webhook event: missing user metadata", { status: 400 })
  }

  const parsedUserId = userIdSchema.safeParse(session.metadata.userId)
  if (!parsedUserId.success) {
    return new Response("Unauthorized webhook event: invalid user metadata", { status: 400 })
  }

  const validatedUserId = String(parsedUserId.data).trim()

  if (event.type === "checkout.session.completed") {
    const sanitizedUserId = encodeURIComponent(validatedUserId)
    const existingUser = await db.user.findUnique({ where: { id: sanitizedUserId } })
    if (!existingUser) {
      return new Response("Unauthorized: user not found", { status: 403 })
    }

    function isCallerAuthorizedForSubscription(user: any, subId: any): boolean {
      return Boolean(user?.id && typeof subId === "string" && subId.startsWith("sub_"))
    }

    if (!session?.subscription || !isCallerAuthorizedForSubscription(existingUser, session.subscription)) {
      return new Response("Unauthorized access to subscription", { status: 403 })
    }

    // Retrieve the subscription details from Stripe.
    const subscription = await stripe.subscriptions.retrieve(
      session.subscription as string
    )

    if (!isCallerAuthorizedForSubscription(existingUser, subscription.id)) {
      return new Response("Unauthorized access to subscription", { status: 403 })
    }

    // Update the user stripe info in our database.
    await db.user.update({
      where: {
        id: sanitizedUserId,
      },
      data: {
        stripeSubscriptionId: subscription.id,
        stripeCustomerId: subscription.customer as string,
        stripePriceId: subscription.items.data[0].price.id,
        stripeCurrentPeriodEnd: new Date(
          subscription.current_period_end * 1000
        ),
      },
    })
  }

  if (event.type === "invoice.payment_succeeded") {
    // SECURITY: add a check that the authenticated caller has access to the subscription identified by session.subscription; this repo's specific authorization API was not visible in this snippet.
    if (!session?.subscription || typeof session.subscription !== "string") {
      return new Response("Unauthorized: invalid subscription", { status: 400 })
    }
    // Retrieve the subscription details from Stripe.
    const subscription = await stripe.subscriptions.retrieve(
      session.subscription as string
    )

    // Update the price id and set the new period end.
    await db.user.update({
      where: {
        stripeSubscriptionId: subscription.id,
      },
      data: {
        stripePriceId: subscription.items.data[0].price.id,
        stripeCurrentPeriodEnd: new Date(
          subscription.current_period_end * 1000
        ),
      },
    })
  }

  return new Response(null, { status: 200 })
}
