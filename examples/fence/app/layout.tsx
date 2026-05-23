import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "fence · toolwall live demo",
  description:
    "Side-by-side proof that toolwall stops indirect prompt injection at the tool–response boundary. Apache-2.0.",
  metadataBase: new URL("https://fence.bryteai.studio"),
  openGraph: {
    title: "fence · toolwall live demo",
    description:
      "Watch an AI agent get exfil'd on the left, and the same agent firewalled on the right — toolwall, four lines of code.",
    url: "https://fence.bryteai.studio",
    siteName: "fence",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "fence · toolwall live demo",
    description: "AI tool-boundary firewall · Apache-2.0",
  },
};

export const viewport = {
  themeColor: "#07080c",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
