import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Quantum Vault Demo',
  description:
    'Interactive threshold cryptography demo — AES-256-GCM + Shamir Secret Sharing + Post-Quantum KEM',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-vault-bg text-white min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
