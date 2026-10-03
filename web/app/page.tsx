"use client";

import {
  useEffect, useMemo, useRef, useState,
  type CSSProperties, type FormEvent, type MouseEvent,
} from "react";

type Sev = "low" | "medium" | "high" | "critical";
type Finding = {
  rule_id: string; description: string; file: string; line: number;
  secret_redacted: string; severity: Sev; confidence: number;
  commit: string | null; author: string | null;
};
type ScanResult = {
  url: string; history: boolean; total: number; truncated: boolean;
  duration_seconds: number; findings: Finding[];
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";
const ORDER: Sev[] = ["critical", "high", "medium", "low"];
const WEIGHT: Record<Sev, number> = { low: 1, medium: 3, high: 6, critical: 10 };
const STEPS = [
  "resolving repository",
  "cloning (shallow, size and time capped)",
  "walking file tree",
  "applying 11 detection rules",
  "measuring shannon entropy",
  "scoring confidence",
  "redacting secrets",
];

function Rain() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current!;
    const ctx = c.getContext("2d")!;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const chars = "01abcdef23456789$#<>/";
    const size = 16;
    let drops: number[] = [];
    const fit = () => {
      c.width = window.innerWidth;
      c.height = window.innerHeight;
      drops = Array.from({ length: Math.ceil(c.width / size) }, () => Math.random() * -50);
    };
    const tick = () => {
      ctx.fillStyle = "rgba(5,8,12,0.12)";
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.fillStyle = "#19f5a3";
      ctx.font = `${size}px monospace`;
      drops.forEach((y, i) => {
        ctx.fillText(chars[(Math.random() * chars.length) | 0], i * size, y * size);
        drops[i] = y * size > c.height && Math.random() > 0.975 ? 0 : y + 1;
      });
    };
    fit();
    window.addEventListener("resize", fit);
    const id = still ? 0 : window.setInterval(tick, 60);
    return () => {
      window.removeEventListener("resize", fit);
      window.clearInterval(id);
    };
  }, []);
  return <canvas ref={ref} className="rain" aria-hidden />;
}

function useCountUp(target: number, ms = 1000) {
  const [v, setV] = useState(0);
  useEffect(() => {
    const t0 = performance.now();
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      setV(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

function Terminal({ history }: { history: boolean }) {
  const steps = useMemo(
    () =>
      history
        ? [...STEPS.slice(0, 3), "replaying every commit on every branch", ...STEPS.slice(3)]
        : STEPS,
    [history],
  );
  const [n, setN] = useState(1);
  const [t, setT] = useState(0);
  useEffect(() => {
    const a = window.setInterval(() => setN((v) => Math.min(v + 1, steps.length)), 1100);
    const b = window.setInterval(() => setT((v) => v + 1), 100);
    return () => {
      window.clearInterval(a);
      window.clearInterval(b);
    };
  }, [steps]);
  return (
    <div className="term" role="status">
      <div className="term-bar">
        <i /><i /><i />
        <span>leakscan scan{history ? " --history" : ""}</span>
        <em>{(t / 10).toFixed(1)}s</em>
      </div>
      <div className="term-body">
        <div className="radar" aria-hidden />
        <ul>
          {steps.slice(0, n).map((s, i) => (
            <li key={s} className={i === n - 1 ? "now" : "done"}>
              <b>{i === n - 1 ? ">" : "+"}</b> {s}
            </li>
          ))}
        </ul>
      </div>
      <div className="bar"><span /></div>
    </div>
  );
}

function Report({ result }: { result: ScanResult }) {
  const counts = ORDER.map((s) => ({ s, n: result.findings.filter((f) => f.severity === s).length }));
  const raw = result.findings.reduce((a, f) => a + WEIGHT[f.severity], 0);
  const score = Math.min(100, raw * 4);
  const total = useCountUp(result.total);
  const shown = useCountUp(score);
  const clean = result.total === 0;
  const tone = clean ? "ok" : score >= 60 ? "critical" : score >= 25 ? "high" : "medium";
  const label = clean ? "CLEAN" : score >= 60 ? "CRITICAL" : score >= 25 ? "ELEVATED" : "LOW";
  const C = 2 * Math.PI * 52;

  function exportJson() {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "leakscan-report.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <section className="report">
      <div className="card summary">
        <div className={`ring ${tone}`}>
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="52" className="track" />
            <circle
              cx="60" cy="60" r="52" className="arc"
              style={{ "--c": C, "--to": C * (1 - score / 100) } as CSSProperties}
            />
          </svg>
          <div><strong>{shown}</strong><small>{label}</small></div>
        </div>
        <div className="stats">
          <p className="big">
            {total}<span> potential secret{result.total === 1 ? "" : "s"}</span>
          </p>
          <p className="meta">
            {result.duration_seconds}s | {result.history ? "full git history" : "current tree"}
            {result.truncated ? " | first 500 shown" : ""}
          </p>
          <div className="sev">
            {counts.map(({ s, n }) => (
              <div key={s} className="sevrow">
                <span>{s}</span>
                <div><i className={s} style={{ width: `${result.total ? (n / result.total) * 100 : 0}%` }} /></div>
                <b>{n}</b>
              </div>
            ))}
          </div>
        </div>
      </div>

      {clean ? (
        <p className="okline">{"// nothing leaked. this repository is clean."}</p>
      ) : (
        <div className="card tablecard">
          <div className="tablehead">
            <span>findings</span>
            <button type="button" onClick={exportJson}>export json</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>sev</th><th>rule</th><th>location</th><th>commit</th><th>secret</th><th>conf</th></tr>
              </thead>
              <tbody>
                {result.findings.map((f, i) => (
                  <tr key={i} className="row" style={{ animationDelay: `${Math.min(i, 20) * 45}ms` }}>
                    <td><span className={`tag ${f.severity}`}>{f.severity}</span></td>
                    <td>{f.rule_id}</td>
                    <td className="mono">{f.file}:{f.line}</td>
                    <td className="mono">{f.commit ?? "HEAD"}</td>
                    <td className="mono redacted">{f.secret_redacted}</td>
                    <td>{f.confidence.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [history, setHistory] = useState(false);
  const [loading, setLoading] = useState(false);
  const [slow, setSlow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  // Wake the free-tier API as soon as the page opens, so the first scan is faster.
  useEffect(() => {
    fetch(`${API_URL}/health`).catch(() => {});
  }, []);

  function spot(e: MouseEvent<HTMLElement>) {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mx", `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty("--my", `${e.clientY - r.top}px`);
  }

  async function runScan(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setSlow(false);
    setError(null);
    setResult(null);
    const timer = window.setTimeout(() => setSlow(true), 7000);
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), history }),
      });
      const data = await res.json();
      if (!res.ok) setError(typeof data.detail === "string" ? data.detail : "Invalid request.");
      else setResult(data as ScanResult);
    } catch {
      setError("Could not reach the scanner API. Is it running?");
    } finally {
      window.clearTimeout(timer);
      setSlow(false);
      setLoading(false);
    }
  }

  return (
    <>
      <Rain />
      <main className="shell">
        <h1 className="glitch" data-text="leakscan">leakscan</h1>
        <p className="lead">
          Point it at a public GitHub repository. It hunts for committed API keys, tokens and
          passwords, including the ones deleted commits ago. Secrets are redacted, and the clone
          is destroyed after the scan.
        </p>

        <form className="card spotcard" onSubmit={runScan} onMouseMove={spot}>
          <div className="row-in">
            <span className="prompt">$</span>
            <input
              type="url" required spellCheck={false}
              placeholder="https://github.com/owner/repo"
              value={url} onChange={(e) => setUrl(e.target.value)}
              aria-label="GitHub repository URL"
            />
            <button className="go" type="submit" disabled={loading || !url.trim()}>
              <span>{loading ? "scanning" : "scan"}</span>
            </button>
          </div>
          <div className="opts">
            <label className="switch">
              <input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} />
              <i /> deep scan: full git history
            </label>
            <button type="button" className="chip" onClick={() => setUrl("https://github.com/princ3szn/leakscan")}>
              try: princ3szn/leakscan
            </button>
          </div>
        </form>

        {loading && <Terminal history={history} />}
        {loading && slow && (
          <p className="wake" role="status">
            Still working. If the server was idle it needs up to a minute to wake up (free
            hosting), and large repositories take longer.
          </p>
        )}
        {error && <p className="error" role="alert">! {error}</p>}
        {result && <Report result={result} />}

        <footer className="foot">
          <a href="https://github.com/princ3szn/leakscan" target="_blank" rel="noreferrer">
            view source on GitHub
          </a>{" "}
          | built by Prince Fumen Aminu
        </footer>
      </main>
    </>
  );
}