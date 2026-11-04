import { getServerSession } from "next-auth/next"
import { z } from "zod"
import DOMPurify from "isomorphic-dompurify"

import { authOptions } from "@/lib/auth"
import { db } from "@/lib/db"
import { userNameSchema } from "@/lib/validations/user"

function userHasPermissionToUpdateUser(user: any, targetUserId: string): boolean {
  if (!user?.id || user.id !== targetUserId) {
    return false
  }
  const role = (user as any)?.role || "user"
  const allowedRoles = ["admin", "editor", "user"]
  return allowedRoles.includes(role)
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

    // Check user in database
    const existingUser = await db.user.findUnique({
      where: {
        id: params.userId,
      },
      select: {
        id: true,
      },
    })
    if (!existingUser || existingUser.id !== session.user.id) {
      return new Response(null, { status: 403 })
    }

    // Get the request body and validate it.
    const body = await req.json()
    const payload = userNameSchema.parse(body)

    const sanitizedName = DOMPurify.sanitize(String(payload.name).trim())

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
