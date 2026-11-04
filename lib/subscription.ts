// @ts-nocheck
// TODO: Fix this when we turn strict mode on.
import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth"
import { UserSubscriptionPlan } from "types"
import { freePlan, proPlan } from "@/config/subscriptions"
import { db } from "@/lib/db"

function callerHasSubscriptionAccess(callerUser: any, targetUserId: string): boolean {
  return Boolean(callerUser?.id && callerUser.id === targetUserId)
}

export async function getUserSubscriptionPlan(
  userId: string
): Promise<UserSubscriptionPlan> {
  const session = await getServerSession(authOptions)
  if (!session?.user || !callerHasSubscriptionAccess(session.user, userId)) {
    throw new Error("Unauthorized access to user subscription data")
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
    stripeCurrentPeriodEnd: user.stripeCurrentPeriodEnd?.getTime(),
    isPro,
  }
}
