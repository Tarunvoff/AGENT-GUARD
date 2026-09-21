import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({
  variable: '--font-sans',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'ActShield — Security Control Plane for Autonomous AI',
  description:
    'ActShield provides identity, authority containment, context provenance, ' +
    'deterministic policy enforcement, threat modeling, and forensic investigation ' +
    'for autonomous and multi-agent AI systems.',
  keywords: [
    'AI security',
    'agent security',
    'multi-agent security',
    'MCP security',
    'policy enforcement',
    'LLM security',
    'threat modeling',
    'agentic AI',
  ],
  robots: 'noindex, nofollow',   // Security console — not for public indexing
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} h-full`}>
      <head>
        {/* IBM Plex Mono for IDs, timestamps, and code */}
        <link
          rel="preconnect"
          href="https://fonts.googleapis.com"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-full antialiased">
        {children}
      </body>
    </html>
  );
}
