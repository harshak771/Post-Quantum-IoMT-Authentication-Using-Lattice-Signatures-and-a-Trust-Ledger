# IoMT Post-Quantum Authentication Using Lattice Signatures and a Trust Ledger

This repository contains an educational prototype for Internet of Medical
Things (IoMT) authentication using lattice-signature-inspired math and a small
hash-chained trust ledger.

The project now uses a React dashboard for the web experience and keeps the
Python implementation as the CLI/reference model.

## What It Demonstrates

- Lattice-style key generation, signing, and verification
- Per-patient public keys and trust-score updates
- A toy hash-chained ledger for registration and verification events
- Batch verification timing for emergency-style traffic
- A React dashboard that can be deployed as a static Vercel site

## Project Structure

- `src/App.jsx` - React dashboard and browser-side demo workflow
- `src/styles.css` - Responsive dashboard styling
- `src/main.jsx` - React entrypoint
- `iot_lattice_auth.py` - Python CLI/reference implementation
- `index.html` - Vite HTML entrypoint
- `vercel.json` - Vercel build and SPA routing config

## Run the React Dashboard

Install Node dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Create a production build:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

## Run the Python CLI Demo

Install Python dependencies:

```bash
pip install numpy matplotlib
```

Run:

```bash
python iot_lattice_auth.py
```

The CLI lets you register patients, sign and verify medical packets, view the
ledger, run a stress test, and simulate emergency batch traffic.

## Cryptographic Flow

At a high level:

1. The system creates a public matrix `X` over the prime field `q`.
2. Each patient gets a small secret vector `x`.
3. The public key is `P = x * X mod q`.
4. A signature chooses a small random vector `r`.
5. It computes `S = r * X mod q`.
6. It hashes the message, `S`, and timestamp into `h`.
7. It computes `s = r + h * x mod q`.
8. Verification checks `s * X == S + h * P mod q`.

## Deployment

This project is configured for Vercel:

```bash
npm run build
```

Vercel serves the generated `dist` folder and routes all paths back to
`index.html` so the React app can handle the dashboard.

## Important Note

This is an academic prototype for learning and demonstrations. It is not
production cryptography, and it should not be used for real patient security,
clinical systems, or regulated medical infrastructure.
