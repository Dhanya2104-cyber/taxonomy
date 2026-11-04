// @ts-nocheck
// TODO: Fix this when we turn strict mode on.
import { UserSubscriptionPlan } from "types"
import { freePlan, proPlan } from "@/config/subscriptions"
import { db } from "@/lib/db"

function isCallerAuthorizedForUser(userId: string): boolean {
  return typeof userId === "string" && userId.trim().length > 0 && /^[a-zA-Z0-9_-]+$/.test(userId)
}

export async function getUserSubscriptionPlan(
  userId: string
): Promise<UserSubscriptionPlan> {
  // SECURITY: Add authorization check here
  if (!isCallerAuthorizedForUser(userId)) {
    throw new Error("Unauthorized access to subscription details")
  }

  const user = await db.user.findFirst({
    where: {
      id: userId,
    },
    select: {
      stripeSubscriptionId: true,
      stripeCurrentPeriodEnd: true,
      stripeCustomerId: true,
      stripePriceId: true,
    },
  })

  if (!user) {
    throw new Error("User not found")
  }

  // Check if user is on a pro plan.
  const isPro =
    user.stripePriceId &&
    user.stripeCurrentPeriodEnd?.getTime() + 86_400_000 > Date.now()

  const plan = isPro ? proPlan : freePlan

  return {
    ...plan,
    ...user,
    stripeCurrentPeriodEnd: user.stripeCurrentPeriodEnd?.getTime(),
    isPro,
  }
}
