import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "IncidentGraph — AgentOps for incident investigation",
  description:
    "Autonomous incident investigation with auditable agents: evidence graphs, deterministic policy, durable tool execution and trajectory evals.",
};

const nav = [
  ["/", "Home"],
  ["/incidents", "Incidents"],
  ["/evals", "Evals"],
  ["/retrieval", "Retrieval"],
  ["/memory", "Memory"],
  ["/security", "Security"],
] as const;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link href="/" className="brand">
            IncidentGraph
          </Link>
          <nav>
            {nav.map(([href, label]) => (
              <Link key={href} href={href}>
                {label}
              </Link>
            ))}
          </nav>
        </header>
        <main>{children}</main>
        <footer className="footer">
          Synthetic demo data. Every number on this dashboard is measured from
          this system&apos;s own runs — never hand-written.
        </footer>
      </body>
    </html>
  );
}
