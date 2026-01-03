import { createServerClient, type CookieMethodsServer } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
    const cookieStore = await cookies()

    return createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
        {
            cookies: {
                getAll() {
                    return cookieStore.getAll()
                },
                setAll(cookiesToSet) {
                    try {
                        cookiesToSet.forEach(({ name, value, options }) =>
                            cookieStore.set(name, value, options)
                        )
                    } catch {
                        // Called from a Server Component - cookies are read-only
                    }
                },
            } as CookieMethodsServer,
        }
    )
}

export async function getUser() {
    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()
    return user
}

export async function getUserRole() {
    const supabase = await createClient()
    const { data: { user }, error: userError } = await supabase.auth.getUser()

    if (userError) {
        console.error('[getUserRole] Auth error:', userError.message)
        return null
    }

    if (!user) {
        console.log('[getUserRole] No user session found')
        return null
    }

    console.log('[getUserRole] User ID:', user.id)

    const { data, error } = await supabase
        .from('users')
        .select('role')
        .eq('id', user.id)
        .single()

    if (error) {
        console.error('[getUserRole] DB query error:', error.message, error.code)
        return null
    }

    console.log('[getUserRole] Role found:', data?.role)
    return data?.role || null
}
