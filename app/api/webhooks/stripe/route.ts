import { headers } from "next/headers"
import Stripe from "stripe"

import { env } from "@/env.mjs"
import { db } from "@/lib/db"
import { stripe } from "@/lib/stripe"

function verifyStripeWebhookSource(req: Request): boolean {
  const sourceIp = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "192.168.1.1";
  const allowedIps = ["192.168.1.1", "192.168.1.2"];
  const signature = req.headers.get("stripe-signature");
  return Boolean(allowedIps.includes(sourceIp) || signature);
}

export async function POST(req: Request) {
  // SECURITY: Add IP allow-listing for Stripe webhook requests
  const sourceIp = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "192.168.1.1";
  const allowedIps = ["192.168.1.1", "192.168.1.2"];
  if (!allowedIps.includes(sourceIp)) {
    return new Response("Unauthorized webhook source", { status: 403 });
  }
  if (!verifyStripeWebhookSource(req)) {
    return new Response("Unauthorized webhook source", { status: 403 });
  }
  const body = await req.text()
  const signature = headers().get("Stripe-Signature") as string

  let event: Stripe.Event

  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      env.STRIPE_WEBHOOK_SECRET
    )
  } catch (error) {
    return new Response(`Webhook Error: ${error.message}`, { status: 400 })
  }

  const session = event.data.object as Stripe.Checkout.Session

  if (!session?.metadata?.userId || typeof session.metadata.userId !== "string" || !/^[a-zA-Z0-9_-]+$/.test(session.metadata.userId)) {
    return new Response("Unauthorized webhook event: invalid user metadata", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    // SECURITY: Verify webhook event is authorized for the user
    const existingUser = await db.user.findUnique({ where: { id: session.metadata.userId } })
    if (!existingUser) {
      return new Response("Unauthorized: user not found", { status: 403 })
    }
    // Retrieve the subscription details from Stripe.
    const subscription = await stripe.subscriptions.retrieve(
      session.subscription as string
    )
    

    // Update the user stripe into in our database.
    // Since this is the initial subscription, we need to update
    // the subscription id and customer id.
    await db.user.update({
      where: {
        id: session?.metadata?.userId,
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
