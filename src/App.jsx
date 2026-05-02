import { useMemo, useRef, useState } from "react";

const Q = 12289;
const M = 64;
const N = 64;
const SEED = 123;

const tabs = [
  "Lattice view",
  "Sign report",
  "Benchmark",
  "Trust ledger",
];

function makeRng(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng, min, max) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function modQ(value) {
  const out = value % Q;
  return out < 0 ? out + Q : out;
}

function makeTimestampNs() {
  const micros = Math.floor(performance.now() * 1000)
    .toString()
    .padStart(9, "0");
  return `${Date.now()}${micros}`;
}

function smallVector(rng, length, bound = 1) {
  return Array.from({ length }, () => randInt(rng, -bound, bound));
}

function vectorMatrixProduct(vector, matrix) {
  const result = Array(N).fill(0);
  for (let col = 0; col < N; col += 1) {
    let total = 0;
    for (let row = 0; row < M; row += 1) {
      total += vector[row] * matrix[row][col];
    }
    result[col] = modQ(total);
  }
  return result;
}

function vectorPreview(vector, count = 16) {
  const head = vector.slice(0, count).join(", ");
  return `[${head}${vector.length > count ? ", ..." : ""}] (len=${vector.length})`;
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function stablePacket(patientId, heartRate, spo2, tempC, includeTemp, profile, timestampNs) {
  const readings = {
    heart_rate_bpm: Number(heartRate),
    spo2_percent: Number(spo2),
  };

  if (includeTemp) {
    readings.temperature_c = Number(tempC);
  }

  return stableStringify({
    patient_id: patientId,
    patient_profile: profile || {},
    readings,
    timestamp_ns: timestampNs,
  });
}

function simpleHashHex(input) {
  const salts = [0x811c9dc5, 0x9e3779b9, 0x85ebca6b, 0xc2b2ae35];
  return salts
    .map((salt) => {
      let h = salt >>> 0;
      for (let i = 0; i < input.length; i += 1) {
        h ^= input.charCodeAt(i);
        h = Math.imul(h, 16777619) >>> 0;
      }
      return h.toString(16).padStart(8, "0");
    })
    .join("")
    .repeat(2);
}

function appendBlock(system, payload) {
  const prevHash = system.ledger.chain.at(-1)?.hash || "0".repeat(64);
  const block = {
    index: system.ledger.chain.length,
    timestamp_ns: makeTimestampNs(),
    payload,
    prev_hash: prevHash,
  };
  block.hash = simpleHashHex(stableStringify(block));
  system.ledger.chain.push(block);
}

function createSystem() {
  const rng = makeRng(SEED);
  const matrix = Array.from({ length: M }, () =>
    Array.from({ length: N }, () => randInt(rng, 0, Q - 1)),
  );
  const system = {
    rng,
    matrix,
    patients: {},
    profiles: {},
    ledger: {
      records: {},
      chain: [],
    },
  };
  appendBlock(system, { type: "GENESIS" });
  return system;
}

function registerPatient(system, patientId, profile) {
  if (system.patients[patientId]) {
    throw new Error("Patient already registered.");
  }

  const secret = smallVector(system.rng, M, 1);
  const publicKey = vectorMatrixProduct(secret, system.matrix);
  system.patients[patientId] = { patientId, secret, publicKey };
  system.profiles[patientId] = profile;
  system.ledger.records[patientId] = {
    patient_id: patientId,
    public_key: publicKey,
    trust_score: 0,
  };
  appendBlock(system, {
    type: "REGISTER",
    patient_id: patientId,
    public_key: publicKey,
  });
}

function updateTrust(system, patientId, delta) {
  const record = system.ledger.records[patientId];
  record.trust_score = Math.max(0, record.trust_score + delta);
  appendBlock(system, {
    type: "TRUST_UPDATE",
    patient_id: patientId,
    trust_score: record.trust_score,
    delta,
  });
}

function fallbackHashToField(input) {
  let h = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return modQ(h >>> 0);
}

async function hashToField(message, S, timestamp) {
  const input = `${message}|${S.join(",")}|${timestamp}`;
  if (!globalThis.crypto?.subtle) {
    return fallbackHashToField(input);
  }

  const encoded = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoded);
  let acc = 0;
  for (const byte of new Uint8Array(digest)) {
    acc = (acc * 256 + byte) % Q;
  }
  return acc;
}

async function signMessage(system, patient, message, timestamp = makeTimestampNs()) {
  const r = smallVector(system.rng, M, 1);
  const S = vectorMatrixProduct(r, system.matrix);
  const h = await hashToField(message, S, timestamp);
  const s = r.map((value, index) => modQ(value + h * patient.secret[index]));
  return { S, s, timestamp };
}

async function verifyMessage(system, message, signature, publicKey) {
  const h = await hashToField(message, signature.S, signature.timestamp);
  const left = vectorMatrixProduct(signature.s.map(modQ), system.matrix);
  const right = signature.S.map((value, index) => modQ(value + h * publicKey[index]));
  return left.every((value, index) => value === right[index]);
}

async function submitAndVerify(system, patientId, packet, signature) {
  const publicKey = system.ledger.records[patientId].public_key;
  const ok = await verifyMessage(system, packet, signature, publicKey);
  updateTrust(system, patientId, ok ? 1 : -1);
  return ok;
}

async function batchVerify(system, messages, signatures, publicKeys) {
  const hashes = await Promise.all(
    signatures.map((sig, index) => hashToField(messages[index], sig.S, sig.timestamp)),
  );

  return signatures.map((sig, index) => {
    const left = vectorMatrixProduct(sig.s.map(modQ), system.matrix);
    const right = sig.S.map((value, col) => modQ(value + hashes[index] * publicKeys[index][col]));
    return left.every((value, col) => value === right[col]);
  });
}

function StatCard({ label, value, detail }) {
  return (
    <article className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </article>
  );
}

function MatrixPreview({ matrix }) {
  const preview = matrix.slice(0, 8).map((row) => row.slice(0, 8));
  return (
    <div className="table-shell">
      <table>
        <tbody>
          {preview.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {row.map((cell, colIndex) => (
                <td key={`${rowIndex}-${colIndex}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LineChart({ rows }) {
  if (!rows.length) {
    return (
      <div className="empty-chart">
        Run the benchmark to draw the verification curve.
      </div>
    );
  }

  const width = 760;
  const height = 280;
  const padding = 34;
  const maxX = Math.max(...rows.map((row) => row.n));
  const maxY = Math.max(...rows.flatMap((row) => [row.standard, row.batch]));

  const point = (row, key) => {
    const x = padding + ((row.n - 1) / Math.max(1, maxX - 1)) * (width - padding * 2);
    const y = height - padding - (row[key] / Math.max(1, maxY)) * (height - padding * 2);
    return `${x},${y}`;
  };

  return (
    <svg className="line-chart" viewBox={`0 0 ${width} ${height}`} role="img">
      <title>Verification time comparison</title>
      <rect x="0" y="0" width={width} height={height} rx="24" />
      <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} />
      <line x1={padding} y1={padding} x2={padding} y2={height - padding} />
      <polyline points={rows.map((row) => point(row, "standard")).join(" ")} className="standard" />
      <polyline points={rows.map((row) => point(row, "batch")).join(" ")} className="batch" />
      <text x={padding} y={24}>0 ms</text>
      <text x={width - padding - 90} y={24}>{maxY.toFixed(2)} ms</text>
      <text x={width - padding - 56} y={height - 10}>{maxX} patients</text>
    </svg>
  );
}

function App() {
  const systemRef = useRef(null);
  if (!systemRef.current) {
    systemRef.current = createSystem();
  }

  const [version, setVersion] = useState(0);
  const [activeTab, setActiveTab] = useState(tabs[0]);
  const [registerForm, setRegisterForm] = useState({
    patientId: "",
    name: "",
    age: "21",
    contact: "",
  });
  const [registerMessage, setRegisterMessage] = useState("");
  const [selectedPatient, setSelectedPatient] = useState("");
  const [signPatient, setSignPatient] = useState("");
  const [packetStamp, setPacketStamp] = useState(() => makeTimestampNs());
  const [signForm, setSignForm] = useState({
    heartRate: 75,
    spo2: 98,
    temperature: 36.8,
    includeTemp: true,
  });
  const [lastSignature, setLastSignature] = useState(null);
  const [benchmarkRows, setBenchmarkRows] = useState([]);
  const [benchmarkBusy, setBenchmarkBusy] = useState(false);
  const [maxPatients, setMaxPatients] = useState(60);
  const [busySign, setBusySign] = useState(false);

  const system = systemRef.current;
  const patientIds = useMemo(
    () => Object.keys(system.patients).sort(),
    [system, version],
  );
  const activePkPatient = patientIds.includes(selectedPatient)
    ? selectedPatient
    : patientIds[0] || "";
  const activeSignPatient = patientIds.includes(signPatient)
    ? signPatient
    : patientIds[0] || "";
  const activeProfile = activeSignPatient ? system.profiles[activeSignPatient] : {};
  const packetPreview = activeSignPatient
    ? stablePacket(
        activeSignPatient,
        signForm.heartRate,
        signForm.spo2,
        signForm.temperature,
        signForm.includeTemp,
        activeProfile,
        packetStamp,
      )
    : "";

  function rerender() {
    setVersion((current) => current + 1);
  }

  function handleRegister(event) {
    event.preventDefault();
    const patientId = registerForm.patientId.trim();
    if (!patientId) {
      setRegisterMessage("Patient ID is required.");
      return;
    }

    try {
      registerPatient(system, patientId, {
        name: registerForm.name.trim(),
        age: Number(registerForm.age) || 0,
        contact: registerForm.contact.trim(),
      });
      setRegisterForm({ patientId: "", name: "", age: "21", contact: "" });
      setRegisterMessage(`${patientId} is now registered.`);
      setSelectedPatient(patientId);
      setSignPatient(patientId);
      rerender();
    } catch (error) {
      setRegisterMessage(error.message);
    }
  }

  async function handleSign(event) {
    event.preventDefault();
    if (!activeSignPatient) {
      return;
    }

    setBusySign(true);
    const packet = stablePacket(
      activeSignPatient,
      signForm.heartRate,
      signForm.spo2,
      signForm.temperature,
      signForm.includeTemp,
      activeProfile,
      packetStamp,
    );
    const patient = system.patients[activeSignPatient];
    const signature = await signMessage(system, patient, packet, packetStamp);
    const verified = await submitAndVerify(system, activeSignPatient, packet, signature);
    const h = await hashToField(packet, signature.S, signature.timestamp);

    setLastSignature({
      patientId: activeSignPatient,
      packet,
      signature,
      h,
      verified,
      trust: system.ledger.records[activeSignPatient].trust_score,
    });
    setPacketStamp(makeTimestampNs());
    setBusySign(false);
    rerender();
  }

  async function runBenchmark() {
    setBenchmarkBusy(true);
    const rows = [];
    const testSystem = createSystem();

    for (let size = 1; size <= maxPatients; size += 1) {
      const messages = [];
      const signatures = [];
      const publicKeys = [];
      const timestamp = makeTimestampNs();

      for (let i = 0; i < size; i += 1) {
        const patientId = `STRESS_${i + 1}`;
        const secret = smallVector(testSystem.rng, M, 1);
        const publicKey = vectorMatrixProduct(secret, testSystem.matrix);
        const message = stableStringify({
          event: "BENCHMARK",
          patient_id: patientId,
          readings: {
            heart_rate_bpm: 70 + (i % 18),
            spo2_percent: 96 + (i % 3),
          },
          timestamp_ns: timestamp,
        });
        const patient = { secret, publicKey };
        const signature = await signMessage(testSystem, patient, message, timestamp);
        messages.push(message);
        signatures.push(signature);
        publicKeys.push(publicKey);
      }

      const loopStart = performance.now();
      for (let i = 0; i < size; i += 1) {
        await verifyMessage(testSystem, messages[i], signatures[i], publicKeys[i]);
      }
      const loopMs = performance.now() - loopStart;

      const batchStart = performance.now();
      await batchVerify(testSystem, messages, signatures, publicKeys);
      const batchMs = performance.now() - batchStart;

      rows.push({
        n: size,
        standard: loopMs,
        batch: batchMs,
      });

      if (size % 10 === 0) {
        setBenchmarkRows([...rows]);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    setBenchmarkRows(rows);
    setBenchmarkBusy(false);
  }

  const latestBlocks = system.ledger.chain.slice(-20).reverse();
  const trustRows = patientIds.map((patientId) => system.ledger.records[patientId]);

  return (
    <main className="app-shell">
      <aside className="side-panel">
        <div className="brand-mark">
          <span>TL</span>
        </div>
        <p className="eyebrow">IoMT authentication lab</p>
        <h1>Trust Lattice</h1>
        <p className="lede">
          A browser-native React dashboard for the post-quantum IoMT demo:
          register a patient, sign a health packet, verify it, and watch the
          trust ledger move.
        </p>

        <div className="side-stats">
          <StatCard label="Matrix" value={`${M} x ${N}`} detail="public X over Zq" />
          <StatCard label="Modulus" value={Q} detail="prime field" />
          <StatCard label="Patients" value={patientIds.length} detail="registered now" />
        </div>

        <form className="register-card" onSubmit={handleRegister}>
          <h2>Register patient</h2>
          <label>
            Patient ID
            <input
              value={registerForm.patientId}
              onChange={(event) =>
                setRegisterForm({ ...registerForm, patientId: event.target.value })
              }
              placeholder="U101"
            />
          </label>
          <label>
            Name
            <input
              value={registerForm.name}
              onChange={(event) =>
                setRegisterForm({ ...registerForm, name: event.target.value })
              }
              placeholder="Alice Sharma"
            />
          </label>
          <div className="split-fields">
            <label>
              Age
              <input
                type="number"
                min="0"
                max="120"
                value={registerForm.age}
                onChange={(event) =>
                  setRegisterForm({ ...registerForm, age: event.target.value })
                }
              />
            </label>
            <label>
              Contact
              <input
                value={registerForm.contact}
                onChange={(event) =>
                  setRegisterForm({ ...registerForm, contact: event.target.value })
                }
                placeholder="+91..."
              />
            </label>
          </div>
          <button type="submit">Add to ledger</button>
          {registerMessage ? <p className="form-note">{registerMessage}</p> : null}
        </form>
      </aside>

      <section className="workspace">
        <nav className="tab-bar" aria-label="Dashboard sections">
          {tabs.map((tab) => (
            <button
              key={tab}
              className={activeTab === tab ? "active" : ""}
              onClick={() => setActiveTab(tab)}
              type="button"
            >
              {tab}
            </button>
          ))}
        </nav>

        {activeTab === "Lattice view" ? (
          <section className="panel-grid two">
            <article className="panel">
              <p className="eyebrow">Public setup</p>
              <h2>System matrix preview</h2>
              <p>
                The dashboard uses the same shape as the original prototype:
                a 64 by 64 public matrix over q = 12289.
              </p>
              <MatrixPreview matrix={system.matrix} />
            </article>

            <article className="panel">
              <p className="eyebrow">Patient credential</p>
              <h2>Public key vector</h2>
              {patientIds.length ? (
                <>
                  <label>
                    Select patient
                    <select
                      value={activePkPatient}
                      onChange={(event) => setSelectedPatient(event.target.value)}
                    >
                      {patientIds.map((patientId) => (
                        <option key={patientId} value={patientId}>
                          {patientId}
                        </option>
                      ))}
                    </select>
                  </label>
                  <pre>{vectorPreview(system.patients[activePkPatient].publicKey, 24)}</pre>
                  <div className="mini-vector">
                    {system.patients[activePkPatient].publicKey.slice(0, 24).map((value, index) => (
                      <span key={index}>{value}</span>
                    ))}
                  </div>
                </>
              ) : (
                <div className="empty-state">
                  Register a patient from the left panel to see a public key.
                </div>
              )}
            </article>
          </section>
        ) : null}

        {activeTab === "Sign report" ? (
          <section className="panel-grid two">
            <article className="panel">
              <p className="eyebrow">QBCPDA-style flow</p>
              <h2>Medical report signing</h2>
              {patientIds.length ? (
                <form className="sign-form" onSubmit={handleSign}>
                  <label>
                    Patient
                    <select
                      value={activeSignPatient}
                      onChange={(event) => setSignPatient(event.target.value)}
                    >
                      {patientIds.map((patientId) => (
                        <option key={patientId} value={patientId}>
                          {patientId}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="profile-strip">
                    <span>{activeProfile?.name || "Unnamed patient"}</span>
                    <span>Age {activeProfile?.age || "n/a"}</span>
                    <span>{activeProfile?.contact || "No contact saved"}</span>
                  </div>
                  <div className="split-fields">
                    <label>
                      Heart rate
                      <input
                        type="number"
                        min="0"
                        max="250"
                        value={signForm.heartRate}
                        onChange={(event) =>
                          setSignForm({ ...signForm, heartRate: event.target.value })
                        }
                      />
                    </label>
                    <label>
                      SpO2
                      <input
                        type="number"
                        min="0"
                        max="100"
                        value={signForm.spo2}
                        onChange={(event) =>
                          setSignForm({ ...signForm, spo2: event.target.value })
                        }
                      />
                    </label>
                  </div>
                  <div className="split-fields">
                    <label>
                      Temperature C
                      <input
                        type="number"
                        min="0"
                        max="50"
                        step="0.1"
                        value={signForm.temperature}
                        onChange={(event) =>
                          setSignForm({ ...signForm, temperature: event.target.value })
                        }
                      />
                    </label>
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={signForm.includeTemp}
                        onChange={(event) =>
                          setSignForm({ ...signForm, includeTemp: event.target.checked })
                        }
                      />
                      Include temperature
                    </label>
                  </div>
                  <p className="eyebrow">Canonical packet</p>
                  <pre>{packetPreview}</pre>
                  <button type="submit" disabled={busySign}>
                    {busySign ? "Signing..." : "Sign and verify"}
                  </button>
                </form>
              ) : (
                <div className="empty-state">
                  Add at least one patient before signing a report.
                </div>
              )}
            </article>

            <article className="panel result-panel">
              <p className="eyebrow">Verification result</p>
              <h2>{lastSignature ? "Latest signature" : "Waiting for report"}</h2>
              {lastSignature ? (
                <>
                  <div className={lastSignature.verified ? "verdict ok" : "verdict bad"}>
                    {lastSignature.verified ? "Accepted" : "Rejected"}
                  </div>
                  <div className="side-stats compact">
                    <StatCard label="Trust score" value={lastSignature.trust.toFixed(2)} />
                    <StatCard label="Hash h" value={lastSignature.h} />
                  </div>
                  <p className="eyebrow">S = r.X mod q</p>
                  <pre>{vectorPreview(lastSignature.signature.S)}</pre>
                  <p className="eyebrow">s = r + h.x mod q</p>
                  <pre>{vectorPreview(lastSignature.signature.s)}</pre>
                  <p className="eyebrow">Timestamp ns</p>
                  <pre>{lastSignature.signature.timestamp}</pre>
                </>
              ) : (
                <div className="empty-state">
                  The next signed packet will show the signature vectors, hash,
                  timestamp, and updated trust score here.
                </div>
              )}
            </article>
          </section>
        ) : null}

        {activeTab === "Benchmark" ? (
          <section className="panel benchmark-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Batch verification</p>
                <h2>Verification time comparison</h2>
              </div>
              <div className="benchmark-controls">
                <label>
                  Max patients
                  <input
                    type="range"
                    min="10"
                    max="100"
                    step="10"
                    value={maxPatients}
                    onChange={(event) => setMaxPatients(Number(event.target.value))}
                  />
                  <span>{maxPatients}</span>
                </label>
                <button type="button" onClick={runBenchmark} disabled={benchmarkBusy}>
                  {benchmarkBusy ? "Running..." : "Run benchmark"}
                </button>
              </div>
            </div>
            <LineChart rows={benchmarkRows} />
            {benchmarkRows.length ? (
              <div className="benchmark-table">
                <table>
                  <thead>
                    <tr>
                      <th>N</th>
                      <th>Standard loop (ms)</th>
                      <th>Batch verify (ms)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchmarkRows
                      .filter((row) => row.n === 1 || row.n % 10 === 0 || row.n === maxPatients)
                      .map((row) => (
                        <tr key={row.n}>
                          <td>{row.n}</td>
                          <td>{row.standard.toFixed(3)}</td>
                          <td>{row.batch.toFixed(3)}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </section>
        ) : null}

        {activeTab === "Trust ledger" ? (
          <section className="panel-grid two">
            <article className="panel">
              <p className="eyebrow">Patient trust</p>
              <h2>Registered credentials</h2>
              {trustRows.length ? (
                <div className="ledger-list">
                  {trustRows.map((record) => (
                    <div key={record.patient_id} className="ledger-row">
                      <span>{record.patient_id}</span>
                      <strong>{record.trust_score.toFixed(2)}</strong>
                      <small>{system.profiles[record.patient_id]?.name || "No profile name"}</small>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">No patient credentials have been written yet.</div>
              )}
            </article>

            <article className="panel">
              <p className="eyebrow">Recent blocks</p>
              <h2>Hash-chained log</h2>
              <div className="block-list">
                {latestBlocks.map((block) => (
                  <div key={block.index} className="block-card">
                    <div>
                      <strong>#{block.index}</strong>
                      <span>{block.payload.type}</span>
                    </div>
                    <small>{block.payload.patient_id || "system"}</small>
                    <code>{block.hash.slice(0, 16)}...</code>
                  </div>
                ))}
              </div>
            </article>
          </section>
        ) : null}
      </section>
    </main>
  );
}

export default App;
