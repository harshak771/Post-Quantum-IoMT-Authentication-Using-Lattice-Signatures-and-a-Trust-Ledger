"""IoMT lattice-based authentication (ISIS-inspired) demo.

Implements the mathematical framework provided:
- Setup: public random matrix X in Z_q^{m x n}
- KeyGen: secret x (small) in Z^m, public P = x·X mod q
- Sign: choose r (small) in Z^m
        S = r·X mod q
        h = H(M || S || timestamp) mod q
        s = r + h·x   (computed in Z_q^m)
        signature sigma = (S, s, timestamp)
- Verify: check s·X == S + h·P (mod q)

This is an educational prototype, not production cryptography.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import numpy as np


def _mod_q(x: np.ndarray, q: int) -> np.ndarray:
    """Return x mod q in [0, q-1] as int64."""
    return np.mod(x, q).astype(np.int64, copy=False)


def _small_vector(length: int, bound: int = 1, rng: np.random.Generator | None = None) -> np.ndarray:
    """Sample a small integer vector in [-bound, bound]^length."""
    rng = rng or np.random.default_rng()
    return rng.integers(-bound, bound + 1, size=(length,), dtype=np.int64)


class LatticeCrypto:
    """Core lattice signature scheme (educational)."""

    def __init__(self, m: int = 64, n: int = 64, q: int = 12289, *, seed: int | None = None):
        if q <= 2 or not self._is_probable_prime(q):
            raise ValueError("q must be a prime modulus (small demo primes are fine)")
        self.m = int(m)
        self.n = int(n)
        self.q = int(q)
        self.rng = np.random.default_rng(seed)

        # Public system matrix X ∈ Z_q^{m×n}
        self.X = self.rng.integers(0, q, size=(self.m, self.n), dtype=np.int64)

    @property
    def matrix_shape(self) -> Tuple[int, int]:
        # X is (m×n)
        return (self.m, self.n)

    @staticmethod
    def _is_probable_prime(p: int) -> bool:
        """Deterministic for small ints; sufficient for demo primes."""
        if p % 2 == 0:
            return p == 2
        d = 3
        while d * d <= p:
            if p % d == 0:
                return False
            d += 2
        return True

    def keygen(self, *, secret_bound: int = 1) -> Tuple[np.ndarray, np.ndarray]:
        """Generate (secret x, public P) for a patient.

        x is small in Z^m (stored as int64). P = x·X mod q in Z_q^n.
        """
        x = _small_vector(self.m, bound=secret_bound, rng=self.rng)
        P = _mod_q(x @ self.X, self.q)
        return x, P

    def _hash_to_field(self, message: str, S: np.ndarray, timestamp: int) -> int:
        """Hash to an integer in Z_q using SHA-256."""
        h = hashlib.sha256()
        h.update(message.encode("utf-8"))
        h.update(b"|")
        h.update(S.astype(np.int64, copy=False).tobytes())
        h.update(b"|")
        h.update(str(timestamp).encode("ascii"))
        digest = h.digest()
        return int.from_bytes(digest, byteorder="big") % self.q

    def sign(self, message: str, secret_x: np.ndarray, *, r_bound: int = 1, timestamp: int | None = None) -> Tuple[np.ndarray, np.ndarray, int]:
        """Sign a message and return (S, s, timestamp)."""
        timestamp = int(timestamp if timestamp is not None else time.time_ns())

        r = _small_vector(self.m, bound=r_bound, rng=self.rng)
        S = _mod_q(r @ self.X, self.q)
        h = self._hash_to_field(message, S, timestamp)

        # s = r + h·x  (work in Z_q)
        s = _mod_q(r + (h * secret_x), self.q)
        return S, s, timestamp

    def verify(self, message: str, signature: Tuple[np.ndarray, np.ndarray, int], public_P: np.ndarray) -> bool:
        """Verify signature (S, s, timestamp) against public key P."""
        S, s, timestamp = signature
        S = _mod_q(np.asarray(S, dtype=np.int64), self.q)
        s = _mod_q(np.asarray(s, dtype=np.int64), self.q)
        P = _mod_q(np.asarray(public_P, dtype=np.int64), self.q)

        h = self._hash_to_field(message, S, int(timestamp))

        left = _mod_q(s @ self.X, self.q)
        right = _mod_q(S + (h * P), self.q)
        return bool(np.array_equal(left, right))

    def batch_verify(
        self,
        messages: Sequence[str],
        signatures: Sequence[Tuple[np.ndarray, np.ndarray, int]],
        public_keys: Sequence[np.ndarray],
    ) -> List[bool]:
        """Verify many signatures simultaneously.

        Uses matrix operations:
        - Stack s vectors into matrix S_mat (k×m)
        - Compute left = S_mat·X (k×n)
        - Compute each h_i, and right_i = S_i + h_i·P_i

        Returns list of booleans, one per signature.
        """
        if not (len(messages) == len(signatures) == len(public_keys)):
            raise ValueError("messages, signatures, public_keys must have the same length")
        k = len(messages)
        if k == 0:
            return []

        S_mat = np.vstack([_mod_q(np.asarray(sig[0], dtype=np.int64), self.q) for sig in signatures])  # (k×n)
        s_mat = np.vstack([_mod_q(np.asarray(sig[1], dtype=np.int64), self.q) for sig in signatures])  # (k×m)
        ts = [int(sig[2]) for sig in signatures]
        P_mat = np.vstack([_mod_q(np.asarray(P, dtype=np.int64), self.q) for P in public_keys])  # (k×n)

        hs = np.array([self._hash_to_field(messages[i], S_mat[i], ts[i]) for i in range(k)], dtype=np.int64)  # (k,)

        left = _mod_q(s_mat @ self.X, self.q)  # (k×n)
        right = _mod_q(S_mat + (hs[:, None] * P_mat), self.q)  # (k×n)

        return [bool(np.array_equal(left[i], right[i])) for i in range(k)]


@dataclass(frozen=True)
class PatientRecord:
    patient_id: str
    public_key: List[int]  # stored as JSON-friendly list
    trust_score: float


class SimpleBlockchainLedger:
    """Very small simulated ledger.

    Stores:
    - Patient public keys (credentials)
    - Patient trust scores

    Also appends an immutable-ish log with hashes (toy blockchain).
    """

    def __init__(self, q: int):
        self.q = int(q)
        self.records: Dict[str, PatientRecord] = {}
        self.chain: List[dict] = []
        self._append_block({"type": "GENESIS"})

    def _append_block(self, payload: dict) -> None:
        prev_hash = self.chain[-1]["hash"] if self.chain else "0" * 64
        block = {
            "index": len(self.chain),
            "timestamp_ns": time.time_ns(),
            "payload": payload,
            "prev_hash": prev_hash,
        }
        block_bytes = json.dumps(block, sort_keys=True).encode("utf-8")
        block["hash"] = hashlib.sha256(block_bytes).hexdigest()
        self.chain.append(block)

    def register_patient(self, patient_id: str, public_key: np.ndarray) -> None:
        pk_list = _mod_q(np.asarray(public_key, dtype=np.int64), self.q).tolist()  # store normalized ints
        self.records[patient_id] = PatientRecord(patient_id=patient_id, public_key=pk_list, trust_score=0.0)
        self._append_block({"type": "REGISTER", "patient_id": patient_id, "public_key": pk_list})

    def update_trust(self, patient_id: str, delta: float) -> None:
        if patient_id not in self.records:
            raise KeyError(f"Unknown patient_id: {patient_id}")
        rec = self.records[patient_id]
        new_score = float(max(0.0, rec.trust_score + delta))
        self.records[patient_id] = PatientRecord(patient_id=patient_id, public_key=rec.public_key, trust_score=new_score)
        self._append_block({"type": "TRUST_UPDATE", "patient_id": patient_id, "trust_score": new_score, "delta": delta})

    def get_public_key(self, patient_id: str) -> np.ndarray:
        rec = self.records[patient_id]
        return np.array(rec.public_key, dtype=np.int64)

    def get_trust(self, patient_id: str) -> float:
        return self.records[patient_id].trust_score

    def pretty_print(self, *, max_blocks: int = 12) -> None:
        print("\n==================== BLOCKCHAIN LEDGER ====================")
        if not self.records:
            print("No patients registered yet.")
        else:
            print("Trust Scores (Patient → Score)")
            print("-----------------------------------------------------------")
            for pid in sorted(self.records.keys()):
                print(f"{pid:<12} → {self.records[pid].trust_score:.2f}")

        print("\nRecent Blocks")
        print("-----------------------------------------------------------")
        tail = self.chain[-max_blocks:] if max_blocks > 0 else self.chain
        for b in tail:
            p = b["payload"]
            summary = p.get("type", "")
            if p.get("type") in {"REGISTER", "TRUST_UPDATE"}:
                summary += f" | patient_id={p.get('patient_id')}"
            print(
                f"#{b['index']:<3} ts={b['timestamp_ns']} type={summary:<28} hash={b['hash'][:12]}.."
            )
        print("===========================================================\n")


class TrustedEntity:
    """Trusted Entity (TE): system setup + registration."""

    def __init__(self, crypto: LatticeCrypto, ledger: SimpleBlockchainLedger):
        self.crypto = crypto
        self.ledger = ledger

    def register(self, patient_id: str, public_key: np.ndarray) -> None:
        self.ledger.register_patient(patient_id, public_key)


class Patient:
    """Patient Ui: generates data and signs it."""

    def __init__(self, patient_id: str, crypto: LatticeCrypto, te: TrustedEntity):
        self.patient_id = patient_id
        self.crypto = crypto
        self.te = te

        self.secret_x, self.public_P = self.crypto.keygen(secret_bound=1)
        self.te.register(self.patient_id, self.public_P)

    def generate_health_packet(self, *, heart_rate_bpm: int) -> str:
        # Keep it simple: a short string packet.
        return f"Patient={self.patient_id}; Heart Rate={heart_rate_bpm}bpm"

    def sign_packet(self, packet: str) -> Tuple[np.ndarray, np.ndarray, int]:
        return self.crypto.sign(packet, self.secret_x, r_bound=1)


class MedicalSpecialist:
    """Medical Specialist (MS): verifies patient signatures."""

    def __init__(self, crypto: LatticeCrypto, ledger: SimpleBlockchainLedger):
        self.crypto = crypto
        self.ledger = ledger

    def verify_packet(self, patient_id: str, packet: str, signature: Tuple[np.ndarray, np.ndarray, int]) -> bool:
        public_key = self.ledger.get_public_key(patient_id)
        return self.crypto.verify(packet, signature, public_key)


class IoMT_System:
    """System glue for Patient ↔ Doctor ↔ Blockchain interaction."""

    def __init__(self, *, m: int = 64, n: int = 64, q: int = 12289, seed: int | None = 42):
        self.crypto = LatticeCrypto(m=m, n=n, q=q, seed=seed)
        self.ledger = SimpleBlockchainLedger(q=self.crypto.q)
        self.te = TrustedEntity(self.crypto, self.ledger)
        self.ms = MedicalSpecialist(self.crypto, self.ledger)

        self.patients: Dict[str, Patient] = {}

    def register_patient(self, patient_id: str) -> Patient:
        if patient_id in self.patients:
            raise ValueError(f"Patient already registered: {patient_id}")
        patient = Patient(patient_id, self.crypto, self.te)
        self.patients[patient_id] = patient
        return patient

    def submit_and_verify(self, patient_id: str, packet: str, signature: Tuple[np.ndarray, np.ndarray, int]) -> bool:
        ok = self.ms.verify_packet(patient_id, packet, signature)
        if ok:
            self.ledger.update_trust(patient_id, delta=1.0)
        else:
            self.ledger.update_trust(patient_id, delta=-1.0)
        return ok


def _print_banner() -> None:
    print("\n===========================================================")
    print("   IoMT Lattice-Based Authentication (PQ Demo Dashboard)   ")
    print("===========================================================")


def _print_security_log(system: IoMT_System, *, patient_id: str, verified: bool) -> None:
    m, n = system.crypto.matrix_shape  # (m×n)
    print("\n------------------------ SECURITY LOG ----------------------")
    print(f"Patient ID           : {patient_id}")
    print(f"Verification Result  : {'ACCEPT' if verified else 'REJECT'}")
    print(f"Modulus (prime) q    : {system.crypto.q}")
    print(f"Lattice Matrix (n×m) : {n} × {m}  (X is stored as m×n = {m}×{n})")
    print("PQ Statement         : Lattice-based assumptions are widely")
    print("                      believed resistant to Shor’s algorithm")
    print("                      (which targets factoring/discrete-log).")
    print("-----------------------------------------------------------\n")


def _prompt_non_empty(prompt: str) -> str:
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Input cannot be empty.")


def _prompt_int(prompt: str, *, min_value: int | None = None, max_value: int | None = None, allow_blank: bool = False) -> int | None:
    while True:
        raw = input(prompt).strip()
        if allow_blank and raw == "":
            return None
        try:
            v = int(raw)
        except ValueError:
            print("Please enter a valid integer.")
            continue
        if min_value is not None and v < min_value:
            print(f"Value must be ≥ {min_value}.")
            continue
        if max_value is not None and v > max_value:
            print(f"Value must be ≤ {max_value}.")
            continue
        return v


def _build_medical_packet(patient_id: str) -> str:
    """Collect a small medical data payload from user input and return it as a canonical JSON string."""
    print("\nEnter medical data (leave blank to skip optional fields).")
    hr = _prompt_int("Heart Rate (bpm): ", min_value=0)
    spo2 = _prompt_int("Oxygen Saturation SpO2 (%): ", min_value=0, max_value=100)
    temp = _prompt_int("Temperature (°C) [optional]: ", allow_blank=True)
    systolic = _prompt_int("Blood Pressure Systolic (mmHg) [optional]: ", allow_blank=True)
    diastolic = _prompt_int("Blood Pressure Diastolic (mmHg) [optional]: ", allow_blank=True)

    payload = {
        "patient_id": patient_id,
        "timestamp_ns": time.time_ns(),
        "readings": {
            "heart_rate_bpm": hr,
            "spo2_percent": spo2,
        },
    }
    if temp is not None:
        payload["readings"]["temperature_c"] = temp
    if systolic is not None and diastolic is not None:
        payload["readings"]["blood_pressure_mmhg"] = {"systolic": systolic, "diastolic": diastolic}

    # Deterministic serialization improves reproducibility of the hash input.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def simulate_emergency_traffic(system: IoMT_System, *, num_patients: int = 50) -> None:
    """Simulate many patients sending data at the same time and verify via batch verification."""
    if num_patients <= 0:
        print("num_patients must be positive.")
        return

    # Ensure enough patients exist.
    created = 0
    while len(system.patients) < num_patients:
        pid = f"EMR_{len(system.patients) + 1}"
        system.register_patient(pid)
        created += 1

    patients = list(system.patients.values())[:num_patients]
    messages: List[str] = []
    signatures: List[Tuple[np.ndarray, np.ndarray, int]] = []
    public_keys: List[np.ndarray] = []
    patient_ids: List[str] = []

    # "Same time" in a simulation means we prepare all packets first.
    base_ts = time.time_ns()
    for idx, p in enumerate(patients):
        msg = json.dumps(
            {
                "patient_id": p.patient_id,
                "timestamp_ns": base_ts,
                "readings": {"heart_rate_bpm": 80 + (idx % 10), "spo2_percent": 96 - (idx % 3)},
                "event": "EMERGENCY_TRAFFIC",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        sig = system.crypto.sign(msg, p.secret_x, r_bound=1, timestamp=base_ts)

        messages.append(msg)
        signatures.append(sig)
        public_keys.append(system.ledger.get_public_key(p.patient_id))
        patient_ids.append(p.patient_id)

    t0 = time.perf_counter()
    results = system.crypto.batch_verify(messages, signatures, public_keys)
    t1 = time.perf_counter()

    accepted = 0
    for pid, ok in zip(patient_ids, results):
        system.ledger.update_trust(pid, delta=1.0 if ok else -1.0)
        accepted += int(ok)

    print("\n================== EMERGENCY TRAFFIC (BATCH) ===============")
    print(f"Patients simulated     : {num_patients} (created {created} new)")
    print(f"Accepted / Total       : {accepted} / {num_patients}")
    print(f"Batch verify time      : {(t1 - t0) * 1e3:.3f} ms")
    print("===========================================================\n")


def run_stress_test_and_plot(system: IoMT_System, *, max_patients: int = 100) -> None:
    """Benchmark single vs batch verification for N=1..max_patients and plot results."""
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        print("matplotlib is required for plotting.")
        print("Install with: pip install matplotlib")
        return

    Ns = list(range(1, max_patients + 1))
    single_ms: List[float] = []
    batch_ms: List[float] = []

    print("\n================= STRESS TEST / BENCHMARK ==================")
    print("Measuring verification time only (signing excluded).")
    print("N from 1 to", max_patients)
    print("-----------------------------------------------------------")

    for N in Ns:
        # Generate N ephemeral keypairs/messages/signatures under the current system matrix X.
        secrets: List[np.ndarray] = []
        pubs: List[np.ndarray] = []
        messages: List[str] = []
        sigs: List[Tuple[np.ndarray, np.ndarray, int]] = []

        base_ts = time.time_ns()
        for i in range(N):
            x, P = system.crypto.keygen(secret_bound=1)
            msg = json.dumps(
                {
                    "patient_id": f"STRESS_{i+1}",
                    "timestamp_ns": base_ts,
                    "readings": {"heart_rate_bpm": 70 + (i % 20), "spo2_percent": 97 - (i % 2)},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            sig = system.crypto.sign(msg, x, r_bound=1, timestamp=base_ts)
            secrets.append(x)
            pubs.append(P)
            messages.append(msg)
            sigs.append(sig)

        # Single verification (loop)
        t0 = time.perf_counter()
        loop_results = [system.crypto.verify(messages[i], sigs[i], pubs[i]) for i in range(N)]
        t1 = time.perf_counter()

        # Batch verification
        t2 = time.perf_counter()
        batch_results = system.crypto.batch_verify(messages, sigs, pubs)
        t3 = time.perf_counter()

        if loop_results != batch_results:
            print(f"Warning: mismatch at N={N} (should not happen)")

        single_ms.append((t1 - t0) * 1e3)
        batch_ms.append((t3 - t2) * 1e3)

        if N in {1, 10, 25, 50, 75, 100}:
            print(f"N={N:<3} single={single_ms[-1]:>8.3f} ms | batch={batch_ms[-1]:>8.3f} ms")

    print("-----------------------------------------------------------")
    print("Benchmark complete. Generating plot...")

    plt.figure(figsize=(10, 6))
    plt.plot(Ns, single_ms, label="Single Verification (loop)", linewidth=2)
    plt.plot(Ns, batch_ms, label="Batch Verification (vectorized)", linewidth=2)
    plt.title("Verification Time vs Number of Patients")
    plt.xlabel("Number of Patients (N)")
    plt.ylabel("Time Taken (ms)")
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.show()


def run_dashboard() -> None:
    system = IoMT_System(m=64, n=64, q=12289, seed=123)

    while True:
        _print_banner()
        print("(1) Register a new Patient")
        print("(2) Input Medical Data and Sign + Verify")
        print("(3) View Blockchain Ledger")
        print("(4) Stress Test / Performance Benchmark (1..100 + plot)")
        print("(5) Emergency Traffic Simulation (50 patients, batch verify)")
        print("(0) Exit")

        choice = input("Select an option: ").strip()

        if choice == "0":
            print("Exiting dashboard.")
            return

        if choice == "1":
            pid = _prompt_non_empty("Enter new Patient ID (e.g., U101): ")
            try:
                system.register_patient(pid)
            except ValueError as e:
                print(str(e))
            else:
                print(f"Patient registered: {pid}")
                print(f"Current total patients: {len(system.patients)}")

        elif choice == "2":
            if not system.patients:
                print("No patients registered yet. Please register first.")
                continue
            pid = _prompt_non_empty("Enter Patient ID to sign data: ")
            if pid not in system.patients:
                print("Unknown Patient ID. Register first.")
                continue

            packet = _build_medical_packet(pid)
            sig = system.patients[pid].sign_packet(packet)
            verified = system.submit_and_verify(pid, packet, sig)
            _print_security_log(system, patient_id=pid, verified=verified)
            print(f"Updated Trust Score ({pid}): {system.ledger.get_trust(pid):.2f}")

        elif choice == "3":
            system.ledger.pretty_print(max_blocks=12)

        elif choice == "4":
            run_stress_test_and_plot(system, max_patients=100)

        elif choice == "5":
            simulate_emergency_traffic(system, num_patients=50)

        else:
            print("Invalid option. Please choose 0-5.")


if __name__ == "__main__":
    run_dashboard()
