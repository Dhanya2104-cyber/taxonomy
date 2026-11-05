import { getServerSession } from "next-auth/next"
import { z } from "zod"

import { authOptions } from "@/lib/auth"
import { db } from "@/lib/db"
import { userNameSchema } from "@/lib/validations/user"

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

    // Users can only update their own account.
    const session = await getServerSession(authOptions)
    if (!session?.user?.id || session.user.id !== params.userId) {
      return new Response("Unauthorized", { status: 403 })
    }

    function userHasUpdatePermission(user: any, targetId: string): boolean {
      return Boolean(user?.id && user.id === targetId)
    }

    function checkPermission(callerId: string, targetId: string): boolean {
      return Boolean(callerId && targetId && callerId === targetId)
    }

    // SECURITY: Add a server-side authorization check here to ensure the user has the necessary permissions to update the specified user account.
    // SECURITY: Add an authorization check here verifying the caller has permission to update the specified user account.
    // Example: checkPermission(session.user.id, params.userId)
    if (!session?.user?.id || !userHasUpdatePermission(session.user, params.userId) || !checkPermission(session.user.id, params.userId)) {
      return new Response(null, { status: 403 })
    }

    // Bounded request body parsing to prevent resource exhaustion
    const rawBody = await req.text()
    if (rawBody.length > 100000) {
      return new Response(JSON.stringify({ error: "Payload too large" }), { status: 413 })
    }
    const body = JSON.parse(rawBody)
    const payload = userNameSchema.parse(body)

    // Ensure the ORM being used properly parameterizes queries. If not, explicitly use parameterized queries or escape user input before including it in the query.
    await db.user.update({
      where: {
        id: session.user.id,
      },
      data: {
        name: payload.name.trim(),
      },
    })

    return new Response(null, { status: 200 })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({ error: 'Invalid input' }), { status: 422 })
    }

    return new Response(null, { status: 500 })
  }
}
