import { getServerSession } from "next-auth"
import DOMPurify from "isomorphic-dompurify"
import * as z from "zod"

import { authOptions } from "@/lib/auth"
import { db } from "@/lib/db"
import { postPatchSchema } from "@/lib/validations/post"

const routeContextSchema = z.object({
  params: z.object({
    postId: z.string(),
  }),
})

export async function DELETE(
  req: Request,
  context: z.infer<typeof routeContextSchema>
) {
  try {
    // Validate the route params.
    const { params } = routeContextSchema.parse(context)

    // Only the post's author can delete it.
    if (!(await verifyCurrentUserHasAccessToPost(params.postId))) {
      return new Response(null, { status: 403 })
    }

    // Delete the post.
    await db.post.delete({
      where: {
        id: params.postId as string,
      },
    })

    return new Response(null, { status: 204 })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify(error.issues), { status: 422 })
    }

    console.error("Unexpected error in DELETE:", (error as any)?.message || "Internal Error")
    // SECURITY: ensure logs are stored securely and not exposed in production.
    return new Response(null, { status: 500 })
  }
}

export async function PATCH(
  req: Request,
  context: z.infer<typeof routeContextSchema>
) {
  try {
    // Validate route params.
    const { params } = routeContextSchema.parse(context)

    // Only the post's author can edit it.
    if (!(await verifyCurrentUserHasAccessToPost(params.postId))) {
      return new Response(null, { status: 403 })
    }

    // Get the request body and validate it.
    const json = await req.json()
    const body = postPatchSchema.parse(json)

    // Sanitize string content (object content should be sanitized on render).
    // SECURITY: ensure the application enforces a Content-Security-Policy (CSP) when rendering post content.
    body.content = typeof body.content === "string" ? DOMPurify.sanitize(body.content, { ALLOWED_TAGS: ['b', 'i', 'a'], ALLOWED_ATTR: ['href'] }) : body.content
    // SECURITY: ensure proper encoding when rendering the content in the frontend.

    // Update the post.
    await db.post.update({
      where: {
        id: params.postId,
      },
      data: {
        title: body.title,
        content: body.content,
      },
    })

    return new Response(null, { status: 200 })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({ error: 'Invalid input' }), { status: 422 })
    }

    console.error("Unexpected error in PATCH:", (error as any)?.message || "Internal Error")
    // SECURITY: ensure logs are stored securely and not exposed in production.
    return new Response(null, { status: 500 })
  }
}

async function verifyCurrentUserHasAccessToPost(postId: string) {
  const session = await getServerSession(authOptions)

  // Without this, authorId: undefined removes the filter in Prisma.
  if (!session?.user?.id) {
    return false
  }

  const count = await db.post.count({
    where: {
      id: postId,
      authorId: session.user.id,
    },
  })

  return count > 0
}
