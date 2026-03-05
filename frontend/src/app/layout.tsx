import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CodeRisk Advisor",
  description:
    "Multi-agent AI security review for Python - JavaScript - TypeScript code. Powered by LangGraph.",
  icons: {
    icon: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
