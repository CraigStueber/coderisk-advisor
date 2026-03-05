import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CodeRisk Advisor",
  description:
    "Multi-agent AI security review for Python code. Powered by LangGraph.",
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
