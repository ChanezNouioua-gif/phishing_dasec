import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MailShield — SOC Threat Intelligence",
  description: "Plateforme de détection de phishing basée sur l\'IA",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}