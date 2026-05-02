from __future__ import annotations

import json
import time
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from iot_lattice_auth import IoMT_System  # uses your existing implementation


st.set_page_config(
    page_title="IoMT Post-Quantum Auth Dashboard",
    page_icon="🩺",
    layout="wide",
)

# ----------------------------
# Helpers
# ----------------------------
def ensure_system() -> IoMT_System:
    if "system" not in st.session_state:
        st.session_state.system = IoMT_System(m=64, n=64, q=12289, seed=123)
    # Store patient profiles (personal details) off-ledger for demo purposes.
    # In real systems, PHI/PII should not be stored on an immutable ledger.
    if "profiles" not in st.session_state:
        st.session_state.profiles = {}  # patient_id -> {"name": str, "age": int, "contact": str}
    return st.session_state.system


def canonical_packet(
    patient_id: str,
    heart_rate: int,
    spo2: int,
    temp_c: float | None,
    *,
    profile: Dict[str, object] | None = None,
) -> str:
    payload = {
        "patient_id": patient_id,
        "timestamp_ns": time.time_ns(),
        "patient_profile": profile or {},
        "readings": {
            "heart_rate_bpm": int(heart_rate),
            "spo2_percent": int(spo2),
        },
    }
    if temp_c is not None:
        payload["readings"]["temperature_c"] = float(temp_c)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def vec_preview(v: np.ndarray, k: int = 16) -> str:
    v = np.asarray(v, dtype=np.int64).reshape(-1)
    head = v[:k].tolist()
    suffix = " ..." if v.size > k else ""
    return f"{head}{suffix} (len={v.size})"


def security_info_box() -> None:
    st.info(
        "Security Info:\n\n"
        "This authentication protocol is based on the Inhomogeneous Small Integer Solution (ISIS) problem, "
        "providing resistance against Shor’s algorithm.",
        icon="🔒",
    )


def lattice_label() -> None:
    st.subheader("Lattice-Based Public Key (Post-Quantum)")


def get_patient_ids(system: IoMT_System) -> List[str]:
    return sorted(system.patients.keys())


# ----------------------------
# Benchmarks (cached)
# ----------------------------
@st.cache_data(show_spinner=False)
def benchmark_times(m: int, n: int, q: int, seed: int, max_n: int, repeats: int) -> Tuple[List[int], List[float], List[float]]:
    """
    Returns:
      Ns: [1..max_n]
            standard_linear_ms: simulated linear baseline (ms)
      lattice_batch_ms: measured batch_verify time (ms)
    """
    system = IoMT_System(m=m, n=n, q=q, seed=seed)
    crypto = system.crypto

    Ns = list(range(1, max_n + 1))
    batch_ms: List[float] = []
    linear_ms: List[float] = []

    # Estimate a per-signature cost from single verification (loop) to simulate a "Standard" baseline.
    # Note: This is a *simulation* baseline for presentation; it is not a real key-distribution protocol.
    # We measure one verify timing and scale linearly.
    # Warm-up
    x, P = crypto.keygen(secret_bound=1)
    msg = json.dumps({"patient_id": "WARMUP", "timestamp_ns": time.time_ns(), "readings": {"heart_rate_bpm": 75, "spo2_percent": 98}}, sort_keys=True, separators=(",", ":"))
    sig = crypto.sign(msg, x, r_bound=1, timestamp=time.time_ns())
    _ = crypto.verify(msg, sig, P)

    # Measure average single-verify time (ms)
    t0 = time.perf_counter()
    for _ in range(200):
        _ = crypto.verify(msg, sig, P)
    t1 = time.perf_counter()
    single_verify_ms = ((t1 - t0) / 200.0) * 1e3

    for N in Ns:
        # Prepare N messages/signatures/public keys
        messages: List[str] = []
        sigs: List[Tuple[np.ndarray, np.ndarray, int]] = []
        pubs: List[np.ndarray] = []
        base_ts = time.time_ns()

        for i in range(N):
            x_i, P_i = crypto.keygen(secret_bound=1)
            msg_i = json.dumps(
                {"patient_id": f"STRESS_{i+1}", "timestamp_ns": base_ts, "readings": {"heart_rate_bpm": 70 + (i % 20), "spo2_percent": 97 - (i % 2)}},
                sort_keys=True,
                separators=(",", ":"),
            )
            sig_i = crypto.sign(msg_i, x_i, r_bound=1, timestamp=base_ts)
            messages.append(msg_i)
            sigs.append(sig_i)
            pubs.append(P_i)

        # Batch verification timing (repeat for stability)
        best = None
        for _ in range(repeats):
            a = time.perf_counter()
            _ = crypto.batch_verify(messages, sigs, pubs)
            b = time.perf_counter()
            ms = (b - a) * 1e3
            best = ms if best is None else min(best, ms)

        batch_ms.append(float(best))
        linear_ms.append(float(single_verify_ms * N))  # linear baseline

    return Ns, linear_ms, batch_ms


# ----------------------------
# UI
# ----------------------------
system = ensure_system()
m, n = system.crypto.matrix_shape
q = system.crypto.q

st.title("IoMT Post-Quantum Authentication Dashboard")
st.caption("Lattice-based authentication demo (ISIS-inspired) with batch verification and trust ledger.")

with st.sidebar:
    st.header("System Status")
    st.write(f"Matrix X shape (m×n): **{m}×{n}**")
    st.write(f"Prime modulus q: **{q}**")
    st.write(f"Registered patients: **{len(system.patients)}**")
    security_info_box()

    st.divider()
    st.subheader("Register Patient")
    new_pid = st.text_input("New Patient ID", placeholder="e.g., U101")
    new_name = st.text_input("Patient Name", placeholder="e.g., Alice Sharma")
    new_age = st.number_input("Age", min_value=0, max_value=120, value=21, step=1)
    new_contact = st.text_input("Contact (optional)", placeholder="e.g., +91-XXXXXXXXXX")
    if st.button("Register", use_container_width=True):
        if not new_pid.strip():
            st.error("Patient ID cannot be empty.")
        elif new_pid in system.patients:
            st.warning("Patient already registered.")
        else:
            pid = new_pid.strip()
            system.register_patient(pid)
            st.session_state.profiles[pid] = {
                "name": new_name.strip(),
                "age": int(new_age),
                "contact": new_contact.strip(),
            }
            st.success(f"Registered: {pid}")


tab1, tab2, tab3, tab4 = st.tabs(
    ["Lattice Visualization", "Signature Breakdown", "Comparison Graph", "Blockchain Ledger"]
)

# --- Tab 1: Lattice Visualization ---
with tab1:
    lattice_label()
    colA, colB = st.columns(2)

    with colA:
        st.markdown("#### System Matrix X (preview)")
        X_preview = system.crypto.X[:10, :10]
        st.dataframe(pd.DataFrame(X_preview), use_container_width=True, height=300)

    with colB:
        st.markdown("#### Patient Public Key Pᵢ (preview)")
        pids = get_patient_ids(system)
        if not pids:
            st.warning("Register at least one patient to view a public key.")
        else:
            pid = st.selectbox("Select Patient", pids, key="pk_patient")
            P = system.ledger.get_public_key(pid)
            st.write(f"Selected: **{pid}**")
            st.code(vec_preview(P, k=24), language="text")

            st.markdown("#### Public Key Vector (first 24 values)")
            P_df = pd.DataFrame({"P_i (mod q)": P[:24].astype(np.int64)})
            st.dataframe(P_df, use_container_width=True, height=300)


# --- Tab 2: Signature Breakdown ---
with tab2:
    st.subheader("Medical Report Signing (QBCPDA Math Breakdown)")
    pids = get_patient_ids(system)
    if not pids:
        st.warning("Register a patient first (sidebar).")
    else:
        left, right = st.columns([1.1, 1.0])

        with left:
            pid = st.selectbox("Patient ID", pids, key="sign_patient")
            profile = st.session_state.profiles.get(pid, {})
            if profile:
                st.caption(
                    f"Patient Profile (off-ledger): Name={profile.get('name','') or '—'} | "
                    f"Age={profile.get('age','—')} | Contact={profile.get('contact','') or '—'}"
                )
            st.markdown("##### Input Medical Data")
            hr = st.number_input("Heart Rate (bpm)", min_value=0, max_value=250, value=75, step=1)
            spo2 = st.number_input("SpO2 (%)", min_value=0, max_value=100, value=98, step=1)
            temp = st.number_input("Temperature (°C) [optional]", min_value=0.0, max_value=50.0, value=36.8, step=0.1)
            include_temp = st.checkbox("Include Temperature", value=True)

            packet = canonical_packet(
                pid,
                int(hr),
                int(spo2),
                float(temp) if include_temp else None,
                profile=profile,
            )
            st.markdown("##### Medical Report Packet (canonical JSON)")
            st.code(packet, language="json")

            if st.button("Sign + Verify", type="primary", use_container_width=True):
                patient = system.patients[pid]
                sig = patient.sign_packet(packet)  # (S, s, timestamp)
                verified = system.submit_and_verify(pid, packet, sig)

                S, s_vec, ts = sig
                h = system.crypto._hash_to_field(packet, np.asarray(S, dtype=np.int64), int(ts))  # educational visibility

                st.session_state.last_sig = {
                    "pid": pid,
                    "packet": packet,
                    "S": np.asarray(S, dtype=np.int64),
                    "s": np.asarray(s_vec, dtype=np.int64),
                    "ts": int(ts),
                    "h": int(h),
                    "verified": bool(verified),
                    "trust": float(system.ledger.get_trust(pid)),
                }

        with right:
            security_info_box()
            st.markdown("##### Result")
            last = st.session_state.get("last_sig")
            if not last:
                st.write("No signature generated yet.")
            else:
                if last["verified"]:
                    st.success("Signature VERIFIED (ACCEPT)")
                else:
                    st.error("Signature FAILED (REJECT)")

                st.metric("Trust Score", f"{last['trust']:.2f}")
                st.markdown("##### Signature Vectors")
                st.write("S = r·X (mod q)")
                st.code(vec_preview(last["S"], k=16), language="text")
                st.write("s = r + (h·x) (mod q)")
                st.code(vec_preview(last["s"], k=16), language="text")

                st.markdown("##### Hash + Parameters")
                st.write(f"h = Hash(M || S || timestamp) mod q  →  **{last['h']}**")
                st.write(f"timestamp (ns): **{last['ts']}**")

                st.markdown("##### Security Log (Verbose)")
                st.code(
                    "\n".join(
                        [
                            f"Patient ID           : {last['pid']}",
                            f"Verification Result  : {'ACCEPT' if last['verified'] else 'REJECT'}",
                            f"Prime modulus q      : {q}",
                            f"Lattice Matrix (n×m) : {n} × {m}  (X stored as m×n = {m}×{n})",
                            "PQ Statement         : Lattice-based assumptions are widely believed",
                            "                      resistant to Shor’s algorithm (factoring/discrete-log).",
                        ]
                    ),
                    language="text",
                )


# --- Tab 3: Comparison Graph ---
with tab3:
    st.subheader("Verification Time Comparison (1 to 100)")
    st.caption("Compares a simulated linear-time baseline (Standard) vs lattice batch verification (vectorized).")

    col1, col2, col3 = st.columns(3)
    with col1:
        max_n = st.slider("Max N", min_value=10, max_value=100, value=100, step=10)
    with col2:
        repeats = st.slider("Benchmark repeats (take best)", min_value=1, max_value=5, value=2, step=1)
    with col3:
        run = st.button("Run Benchmark + Plot", type="primary", use_container_width=True)

    security_info_box()

    if run:
        with st.spinner("Running benchmark..."):
            Ns, linear_ms, batch_ms = benchmark_times(m=m, n=n, q=q, seed=123, max_n=max_n, repeats=repeats)

        df = pd.DataFrame(
            {
                "N (patients)": Ns,
                "Simulated Standard (ms)": linear_ms,
                "Lattice Batch Verify (ms)": batch_ms,
            }
        )

        st.dataframe(df, use_container_width=True, height=260)

        fig, ax = plt.subplots(figsize=(10, 5.5))
        ax.plot(Ns, linear_ms, label="Simulated Standard (linear)", linewidth=2)
        ax.plot(Ns, batch_ms, label="Lattice Batch (vectorized)", linewidth=2)
        ax.set_title("Time Taken vs Number of Patients")
        ax.set_xlabel("Number of Patients (N)")
        ax.set_ylabel("Time Taken (ms)")
        ax.grid(True, linestyle="--", alpha=0.4)
        ax.legend()
        st.pyplot(fig)


# --- Tab 4: Blockchain Ledger ---
with tab4:
    st.subheader("Blockchain Ledger (Trust + Logs)")
    security_info_box()

    st.markdown("#### Patient Profiles (off-ledger demo)")
    if not st.session_state.profiles:
        st.caption("No profiles saved yet. Register a patient from the sidebar.")
    else:
        profiles_df = pd.DataFrame(
            [
                {
                    "patient_id": pid,
                    "name": st.session_state.profiles.get(pid, {}).get("name", ""),
                    "age": st.session_state.profiles.get(pid, {}).get("age", ""),
                    "contact": st.session_state.profiles.get(pid, {}).get("contact", ""),
                }
                for pid in sorted(st.session_state.profiles.keys())
            ]
        )
        st.dataframe(profiles_df, use_container_width=True, height=180)

    if not system.ledger.records:
        st.warning("No patients registered yet.")
    else:
        trust_df = pd.DataFrame(
            [{"patient_id": pid, "trust_score": system.ledger.get_trust(pid)} for pid in sorted(system.ledger.records.keys())]
        )
        st.markdown("#### Trust Scores")
        st.dataframe(trust_df, use_container_width=True, height=220)

    st.markdown("#### Recent Blocks")
    tail = system.ledger.chain[-20:]
    blocks_df = pd.DataFrame(
        [
            {
                "index": b["index"],
                "timestamp_ns": b["timestamp_ns"],
                "type": b["payload"].get("type"),
                "patient_id": b["payload"].get("patient_id"),
                "hash_prefix": b["hash"][:12],
                "prev_hash_prefix": b["prev_hash"][:12],
            }
            for b in tail
        ]
    )
    st.dataframe(blocks_df, use_container_width=True, height=320)