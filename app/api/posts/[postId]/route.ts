import { getServerSession } from "next-auth"
import DOMPurify from "dompurify"
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

    // SECURITY: Add a check that verifies the user's role or permissions for post deletion.
    const session = await getServerSession(authOptions)
    if (!session?.user?.id) {
      return new Response(null, { status: 403 })
    }

    function userHasEditPermission(user: any, postId: string): boolean {
      return Boolean(user?.id)
    }
    // SECURITY: Add a role or permission check here to ensure the user is authorized to edit the post.
    if (!userHasEditPermission(session?.user, params.postId)) {
      return new Response(null, { status: 403 })
    }
    // Check if the user has access to this post.
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

    console.error('Unexpected error in DELETE:', error);
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

    const session = await getServerSession(authOptions)

    function userHasEditPermission(user: any, postId: string): boolean {
      return Boolean(user?.id)
    }
    // SECURITY: Add a role or permission check here to ensure the user is authorized to edit the post.
    if (!userHasEditPermission(session?.user, params.postId)) {
      return new Response(null, { status: 403 })
    }
    // Check if the user has access to this post.
    if (!(await verifyCurrentUserHasAccessToPost(params.postId))) {
      return new Response(null, { status: 403 })
    }

    // Get the request body and validate it.
    const json = await req.json()
    const body = postPatchSchema.parse(json)

    // Update the post.
    // SECURITY: Ensure that the application enforces a Content-Security-Policy (CSP) when rendering post content.
    body.content = typeof body.content === "string" ? DOMPurify.sanitize(body.content) : body.content
    await db.post.update({
      where: {
        id: params.postId,
      },
      data: {
        title: body.title,
        content: body.content,
      },
    })

    // Add a Content-Security-Policy header in the HTTP response.
    return new Response(null, {
      status: 200,
      headers: {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none';",
      },
    })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify(error.issues), { status: 422 })
    }

    return new Response(null, { status: 500 })
  }
}

async function verifyCurrentUserHasAccessToPost(postId: string) {
  const session = await getServerSession(authOptions)
  const count = await db.post.count({
    where: {
      id: postId,
      authorId: session?.user.id,
    },
  })

  return count > 0
}
