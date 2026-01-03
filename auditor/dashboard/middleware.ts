import { createServerClient } from '@supabase/ssr'
import { jwtVerify } from 'jose'
import { NextResponse, type NextRequest } from 'next/server'

// Cache the secret key for performance
let cachedSecret: Uint8Array | null = null

function getJwtSecret(): Uint8Array {
    if (cachedSecret) return cachedSecret
    const secret = process.env.SUPABASE_JWT_SECRET
    if (!secret) {
        console.warn('[Middleware] SUPABASE_JWT_SECRET not set, falling back to session-only check')
        return new Uint8Array(0)
    }
    cachedSecret = new TextEncoder().encode(secret)
    return cachedSecret
}

async function verifyJwt(token: string): Promise<{ valid: boolean; payload?: any }> {
    const secret = getJwtSecret()
    if (secret.length === 0) {
        // No secret configured, skip JWT verification
        return { valid: true }
    }

    try {
        const { payload } = await jwtVerify(token, secret, {
            algorithms: ['HS256']
        })
        return { valid: true, payload }
    } catch (error) {
        console.error('[Middleware] JWT verification failed:', error)
        return { valid: false }
    }
}

export async function middleware(request: NextRequest) {
    let supabaseResponse = NextResponse.next({
        request,
    })

    const supabase = createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
        {
            cookies: {
                getAll() {
                    return request.cookies.getAll()
                },
                setAll(cookiesToSet) {
                    cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value))
                    supabaseResponse = NextResponse.next({
                        request,
                    })
                    cookiesToSet.forEach(({ name, value, options }) =>
                        supabaseResponse.cookies.set(name, value, options)
                    )
                },
            },
        }
    )

    // Check if user has a session
    const { data: { user } } = await supabase.auth.getUser()

    // If no session and not on login page, redirect to login
    if (!user && !request.nextUrl.pathname.startsWith('/login')) {
        const url = request.nextUrl.clone()
        url.pathname = '/login'
        return NextResponse.redirect(url)
    }

    // If user exists, verify the JWT token for additional security
    if (user) {
        // Get the Supabase project ref from URL
        const projectRef = new URL(process.env.NEXT_PUBLIC_SUPABASE_URL!).hostname.split('.')[0]
        const cookiePrefix = `sb-${projectRef}-auth-token`

        // Supabase may store token across chunked cookies (e.g., sb-xxx-auth-token.0, sb-xxx-auth-token.1)
        const cookies = request.cookies.getAll()
        const authCookies = cookies
            .filter(c => c.name.startsWith(cookiePrefix))
            .sort((a, b) => a.name.localeCompare(b.name))

        if (authCookies.length > 0) {
            try {
                // Combine chunked cookies
                const combinedValue = authCookies.map(c => c.value).join('')

                // Try to parse as JSON (may be base64 encoded)
                let tokenData: any
                try {
                    tokenData = JSON.parse(combinedValue)
                } catch {
                    // Try base64 decode first
                    try {
                        const decoded = atob(combinedValue)
                        tokenData = JSON.parse(decoded)
                    } catch {
                        tokenData = null
                    }
                }

                const jwt = tokenData?.access_token

                if (jwt && typeof jwt === 'string') {
                    const { valid } = await verifyJwt(jwt)

                    if (!valid) {
                        // Invalid JWT - clear session and redirect to login
                        console.warn('[Middleware] JWT verification failed, clearing session')
                        const url = request.nextUrl.clone()
                        url.pathname = '/login'
                        const response = NextResponse.redirect(url)
                        // Clear all auth cookies
                        authCookies.forEach(c => response.cookies.delete(c.name))
                        return response
                    } else {
                        console.log('[Middleware] JWT verified successfully')
                    }
                }
            } catch (e) {
                // If token parsing fails, continue with session-based auth
                console.warn('[Middleware] Could not parse access token, continuing with session check')
            }
        }

        // If user is logged in and on login page, redirect to dashboard
        if (request.nextUrl.pathname.startsWith('/login')) {
            const url = request.nextUrl.clone()
            url.pathname = '/'
            return NextResponse.redirect(url)
        }
    }

    // Set pathname header for layout to detect current route
    supabaseResponse.headers.set('x-pathname', request.nextUrl.pathname)

    return supabaseResponse
}

export const config = {
    matcher: [
        /*
         * Match all request paths except:
         * - _next/static (static files)
         * - _next/image (image optimization files)
         * - favicon.ico (favicon file)
         * - public folder assets
         */
        '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
    ],
}
