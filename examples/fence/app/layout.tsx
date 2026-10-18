import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "toolwall v0.2 · fence",
  description:
    "toolwall checks tool responses for indirect prompt injection. Real outputs of v0.2.0, including a miss, and its held-out results.",
  metadataBase: new URL("https://fence.bryteai.studio"),
  openGraph: {
    title: "toolwall v0.2 · fence",
    description:
      "Real outputs of toolwall v0.2.0 on three tool responses, including a miss, and its held-out results.",
    url: "https://fence.bryteai.studio",
    siteName: "fence",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "toolwall v0.2 · fence",
    description: "Indirect prompt injection detection at the tool-response boundary · Apache-2.0",
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
