import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const inter = Inter({
  variable: '--font-inter',
  subsets: ['latin'],
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  variable: '--font-mono',
  subsets: ['latin'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'AgentGuard — Security Control Plane for Autonomous AI',
  description:
    'AgentGuard gives autonomous AI systems identity, authority, context provenance, deterministic policy enforcement, and execution evidence.',
  keywords: ['AI security', 'agent security', 'multi-agent', 'MCP security', 'policy enforcement', 'LLM security'],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} h-full dark`}>
      <body className="min-h-full bg-[#090d16] text-zinc-100 antialiased">
        {children}
      </body>
    </html>
  );
}
