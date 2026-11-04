import { getToken } from "next-auth/jwt"
import { withAuth } from "next-auth/middleware"
import { NextResponse } from "next/server"

export default withAuth(
  async function middleware(req) {
    const token = await getToken({ req })
    const isAuth = !!token
    const isAuthPage =
      req.nextUrl.pathname.startsWith("/login") ||
      req.nextUrl.pathname.startsWith("/register")

    if (isAuthPage) {
      if (isAuth) {
        return NextResponse.redirect(new URL("/dashboard", req.url))
      }

      return null
    }

    if (!isAuth) {
      let from = req.nextUrl.pathname;
      if (req.nextUrl.search) {
        from += req.nextUrl.search;
      }
      if (!from.startsWith("/")) {
        from = "/dashboard";
      }
      // Validate 'from' to ensure it only contains allowed paths
      const allowedPaths = ["/dashboard", "/editor", "/login", "/register"];
      if (!allowedPaths.includes(from)) {
        // SECURITY: Ensure 'from' is strictly validated and sanitized
        from = '/dashboard';
      } else {
        from = encodeURIComponent(from);
      }

      return NextResponse.redirect(
        new URL(`/login?from=${from}`, req.url)
      );
    }
  },
  {
    callbacks: {
      async authorized() {
        // This is a work-around for handling redirect on auth pages.
        // We return true here so that the middleware function above
        // is always called.
        return true
      },
    },
  }
)

export const config = {
  matcher: ["/dashboard/:path*", "/editor/:path*", "/login", "/register"],
}
