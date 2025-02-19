import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import type { NextRequest } from 'next/server';

export async function middleware(req: NextRequest) {
  try {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
    console.log("Middleware Debug - Token:", token);
    console.log("Request Path:", req.nextUrl.pathname);

    const isAuth = !!token;
    const isLoginPage = req.nextUrl.pathname === '/login';
    const isForgetPasswordPage = req.nextUrl.pathname === '/ForgetPassword';

    // If authenticated, prevent access to login and forgot password pages
    if (isAuth && (isLoginPage || isForgetPasswordPage)) {
      console.log("Redirecting authenticated user to /dashboard");
      return NextResponse.redirect(new URL('/dashboard', req.url));
      // DashBoard is the correct route name.
    }

    // If unauthenticated, prevent access to protected routes
    if (!isAuth && (req.nextUrl.pathname.startsWith('/dashboard') || req.nextUrl.pathname.startsWith('/pay'))) {
      console.log("Redirecting unauthenticated user to /login");
      return NextResponse.redirect(new URL('/login', req.url));
    }

    return NextResponse.next();
  } catch (error) {
    console.error("Middleware Error:", error);
    return NextResponse.next(); // Allow the request instead of breaking the app
  }
}

export const config = {
  matcher: ['/dashboard/:path*', '/login', '/pay/:path*', '/forgetpassword'],
};