# IoMT Post-Quantum Authentication Using Lattice Signatures and a Trust Ledger

This repository contains a **Python 3** educational prototype of a lattice-based authentication/signature flow for an Internet of Medical Things (IoMT) scenario. It demonstrates post-quantum inspired signatures, a toy trust ledger, and batch verification for high-throughput medical telemetry.

## Features

- Lattice-based key generation, signing, and verification (ISIS-inspired)
- Per-patient public keys and a toy hash-chained trust ledger
- Batch verification for emergency traffic simulations
- CLI demo flow + Streamlit dashboard UI

## Cryptographic Flow (High Level)

- Public matrix **X** over a prime field **q**
- Patient secret **x** (small vector), public key **P = x·X (mod q)**
- Signature on message **M**: choose small **r**, compute **S = r·X (mod q)**, hash **h = H(M || S || timestamp) mod q**, and **s = r + h·x (mod q)**
- Verify: **s·X ≡ S + h·P (mod q)**
- Batch verification uses stacked matrix operations for efficiency

## Project Structure

- `iot_lattice_auth.py` - Core lattice crypto, ledger, CLI demo, benchmarks
- `web.py` - Streamlit dashboard
- `README.md` - Project documentation

## Quick Start (CLI)

```bash
python iot_lattice_auth.py
```

The CLI menu lets you:
- Register new patients
- Enter medical data and sign + verify it
- View the blockchain ledger (trust scores + recent logs)
- Run a stress-test benchmark (1..100 patients) and plot single vs batch verification time
- Run an emergency traffic batch simulation (50 concurrent patients)

## Run the Streamlit Dashboard

```bash
pip install streamlit numpy pandas matplotlib
streamlit run web.py
```

## Dependencies

- `numpy`
- `pandas` (Streamlit dashboard)
- `matplotlib` (plots)
- `streamlit` (UI)

Install:

```bash
pip install numpy pandas matplotlib streamlit
```

## Notes

- This is an **academic prototype** intended for learning and demos.
- It is **not** hardened cryptography and should not be used in production.
