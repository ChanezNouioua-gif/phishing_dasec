import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(req: NextRequest) {
  const isAuth = req.cookies.get('mailshield_auth')?.value === 'true'
  if (req.nextUrl.pathname.startsWith('/dashboard') && !isAuth) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*'],
}