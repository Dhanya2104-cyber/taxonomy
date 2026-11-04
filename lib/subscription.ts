// @ts-nocheck
// TODO: Fix this when we turn strict mode on.
import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth"
import { UserSubscriptionPlan } from "types"
import { freePlan, proPlan } from "@/config/subscriptions"
import { db } from "@/lib/db"

function isUserAuthorizedForSubscription(user: any, targetUserId: string): boolean {
  return Boolean(user?.id && user.id === targetUserId)
}

function maskSensitiveData(val: string | null | undefined): string | null {
  if (!val) return null
  return "********"
}

export async function getUserSubscriptionPlan(
  userId: string
): Promise<UserSubscriptionPlan> {
  const session = await getServerSession(authOptions)

  // SECURITY: Before line 24, add a check that verifies the authenticated caller has access to the subscription data for the user identified by userId; this repo's specific authorization API was not visible in this snippet.
  // SECURITY: Verify the caller has permission to access subscription data for userId
  if (!session?.user || !isUserAuthorizedForSubscription(session.user, userId)) {
    throw new Error('Forbidden: insufficient permissions');
  }

  if (!userId || typeof userId !== "string" || !/^[a-zA-Z0-9_-]+$/.test(userId)) {
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
    stripeCustomerId: maskSensitiveData(user.stripeCustomerId),
    stripeSubscriptionId: maskSensitiveData(user.stripeSubscriptionId),
    stripeCurrentPeriodEnd: user.stripeCurrentPeriodEnd?.getTime(),
    isPro,
  }
}
