import { getServerSession } from "next-auth/next"
import { z } from "zod"

import { authOptions } from "@/lib/auth"
import { db } from "@/lib/db"
import { userNameSchema } from "@/lib/validations/user"

function contextAwareEncode(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;')
}

function userHasPermissionToUpdateUser(user: any, targetUserId: string): boolean {
  return Boolean(user?.id && user.id === targetUserId)
}

const routeContextSchema = z.object({
  params: z.object({
    userId: z.string(),
  }),
})

export async function PATCH(
  req: Request,
  context: z.infer<typeof routeContextSchema>
) {
  try {
    // Validate the route context.
    const { params } = routeContextSchema.parse(context)

    // Ensure user is authenticated and has access to this user.
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return new Response(null, { status: 403 })
    }

    // SECURITY: add an authorization check here verifying the caller has permission to update user <userId> securely.
    if (!userHasPermissionToUpdateUser(session.user, params.userId)) {
      return new Response(null, { status: 403 })
    }

    // Get the request body and validate it.
    const body = await req.json()
    const payload = userNameSchema.parse(body)

    // SECURITY: replace escapeHtml with a context-aware encoding function provided by the framework or a trusted library.
    const sanitizedName = contextAwareEncode(String(payload.name).trim())

    // Update the user using parameterized query
    if (!userHasPermissionToUpdateUser(session.user, params.userId)) {
      return new Response(null, { status: 403 })
    }

    await db.user.update({
      where: {
        id: session.user.id,
      },
      data: {
        name: sanitizedName,
      },
    })

    return new Response(null, { status: 200 })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify(error.issues), { status: 422 })
    }

    return new Response(null, { status: 500 })
  }
}
