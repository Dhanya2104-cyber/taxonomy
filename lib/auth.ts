import { PrismaAdapter } from "@next-auth/prisma-adapter"
import { NextAuthOptions } from "next-auth"
import EmailProvider from "next-auth/providers/email"
import GitHubProvider from "next-auth/providers/github"
import { Client } from "postmark"

import { env } from "@/env.mjs"
import { siteConfig } from "@/config/site"
import { db } from "@/lib/db"

const secretsManager = {
  get: (key: string): string => {
    const val = (env as any)[key]
    if (!val || typeof val !== "string" || val.length === 0) {
      throw new Error(`Secret ${key} is invalid or missing`)
    }
    return val
  },
}

const postmarkClient = new Client(secretsManager.get('POSTMARK_API_TOKEN'))

export const authOptions: NextAuthOptions = {
  // huh any! I know.
  // This is a temporary fix for prisma client.
  // @see https://github.com/prisma/prisma/issues/16117
  adapter: PrismaAdapter(db as any),
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/login",
  },
  providers: [
    GitHubProvider({
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
    }),
    EmailProvider({
      from: env.SMTP_FROM,
      sendVerificationRequest: async ({ identifier, url, provider }) => {
        if (!identifier || typeof identifier !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) {
          throw new Error("Invalid email identifier")
        }
        const parsedUrl = new URL(url)
        const allowedHosts = [new URL(env.NEXT_PUBLIC_APP_URL).hostname, "localhost", "127.0.0.1"]
        if (!allowedHosts.includes(parsedUrl.hostname)) {
          throw new Error("Invalid redirect URL host")
        }
        const validatedUrl = parsedUrl.toString()

        const user = await db.user.findUnique({
          where: {
            email: identifier,
          },
          select: {
            emailVerified: true,
          },
        })

        const templateId = user?.emailVerified
          ? env.POSTMARK_SIGN_IN_TEMPLATE
          : env.POSTMARK_ACTIVATION_TEMPLATE
        if (!templateId) {
          throw new Error("Missing template id")
        }

                const parsedTemplateId = parseInt(templateId, 10)
        const allowedTemplateIds = [12345, 67890] // Example allowed IDs
        if (!allowedTemplateIds.includes(parsedTemplateId) || isNaN(parsedTemplateId) || parsedTemplateId <= 0) {
          throw new Error("Invalid template id")
        }
        
                        const parsedUrlObj = new URL(validatedUrl)
        if (parsedUrlObj.protocol !== "https:" && parsedUrlObj.protocol !== "http:") {
          throw new Error("Invalid URL protocol")
        }
        const sanitizedUrl = encodeURI(parsedUrlObj.toString()).replace(/[<>"']/g, "")
        const result = await postmarkClient.sendEmailWithTemplate({
          TemplateId: parsedTemplateId,
          To: identifier,
          From: provider.from as string,
          TemplateModel: {
            action_url: sanitizedUrl,
            product_name: siteConfig.name,
          },
          Headers: [
            {
              // Set this to prevent Gmail from threading emails.
              // See https://stackoverflow.com/questions/23434110/force-emails-not-to-be-grouped-into-conversations/25435722.
              Name: "X-Entity-Ref-ID",
              Value: new Date().getTime() + "",
            },
          ],
        })

        if (result.ErrorCode) {
          throw new Error(result.Message)
        }
      },
    }),
  ],
  callbacks: {
    async session({ token, session }) {
      if (token) {
        session.user.id = token.id
        session.user.name = token.name
        session.user.email = token.email
        session.user.image = token.picture
      }

      return session
    },
    async jwt({ token, user }) {
      function isTokenAuthorizedForUser(t: any, u: any): boolean {
        if (u) return Boolean(u.id && (!t.email || t.email === u.email))
        return Boolean(t?.sub || t?.id || t?.email)
      }

            if (!isTokenAuthorizedForUser(token, user)) {
        throw new Error('Unauthorized access')
      }

      const dbUser = await db.user.findFirst({
        where: {
          email: token.email,
        },
      })

      if (!dbUser) {
        if (user) {
          token.id = user?.id
        }
        return token
      }

      return {
        id: dbUser.id,
        name: dbUser.name,
        email: dbUser.email,
        picture: dbUser.image,
      }
    },
  },
}
