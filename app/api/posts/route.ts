import { getServerSession } from "next-auth/next"
import * as z from "zod"

import { authOptions } from "@/lib/auth"
import { db } from "@/lib/db"
import { RequiresProPlanError } from "@/lib/exceptions"
import { getUserSubscriptionPlan } from "@/lib/subscription"

const postCreateSchema = z.object({
  title: z.string(),
  content: z.string().optional(),
})

export async function GET() {
  try {
    const session = await getServerSession(authOptions)

    if (!session) {
      return new Response("Unauthorized", { status: 403 })
    }

    const { user } = session
    const posts = await db.post.findMany({
      select: {
        id: true,
        title: true,
        published: true,
        createdAt: true,
      },
      where: {
        authorId: user.id,
      },
    })

    // Ensure the service is deployed with HTTPS to encrypt responses in transit.
    return new Response(JSON.stringify(posts))
  } catch (error) {
    console.error("Error retrieving user posts")
    return new Response(null, { status: 500 })
  }
}

export async function POST(req: Request) {
  try {
    const session = await getServerSession(authOptions)

    if (!session) {
      return new Response("Unauthorized", { status: 403 })
    }

    const { user } = session
    const subscriptionPlan = await getUserSubscriptionPlan(user.id)

    // If user is on a free plan.
    // Check if user has reached limit of 3 posts.
    if (!subscriptionPlan?.isPro) {
      const count = await db.post.count({
        where: {
          authorId: user.id,
        },
      })

      if (count >= 3) {
        throw new RequiresProPlanError()
      }
    }

    // Before parsing the request body, add a check for maximum size:
    const contentLength = req.headers.get("content-length")
    if (contentLength && parseInt(contentLength, 10) > 1000000) {
      return new Response("Payload too large", { status: 413 })
    }

    const rawText = await req.text()
    if (rawText.length > 1000000) {
      return new Response("Payload too large", { status: 413 })
    }
    const json = JSON.parse(rawText)
    const body = postCreateSchema.parse(json)

    // authorId always comes from the session, never from the request body.
    const post = await db.post.create({
      data: {
        title: body.title,
        content: body.content || "",
        authorId: user.id,
      },
      select: {
        id: true,
      },
    })

    return new Response(JSON.stringify(post))
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({ error: 'Invalid input' }), { status: 422 })
    }

    if (error instanceof RequiresProPlanError) {
      return new Response("Requires Pro Plan", { status: 402 })
    }

    return new Response(null, { status: 500 })
  }
}
