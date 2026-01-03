import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { getUserRole } from "@/lib/supabaseServer";
import { headers } from "next/headers";
import AccessDenied from "@/components/auth/AccessDenied";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sentinel Auditor | Dashboard",
  description: "AI-Powered Security Monitoring and Audit Intelligence Platform",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Get the current path to check if we're on login page
  const headersList = await headers();
  const pathname = headersList.get("x-pathname") || "";
  const isLoginPage = pathname.startsWith("/login");

  // Skip role check for login page
  let isAdmin = true;
  if (!isLoginPage) {
    const role = await getUserRole();
    isAdmin = role === "admin";
  }

  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
        suppressHydrationWarning
      >
        {isAdmin ? children : <AccessDenied />}
      </body>
    </html>
  );
}
