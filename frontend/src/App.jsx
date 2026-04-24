import { useState } from "react";

const API_URL = "http://127.0.0.1:8000/predict";
const EXAMPLE_QUERIES = [
  "' OR '1'='1",
  "SELECT * FROM products WHERE id = 10",
  "UNION SELECT username, password FROM users",
  "admin' --",
];

function ResultCard({ result }) {
  if (!result) {
    return null;
  }

  const isMalicious = result.label === 1;
  const reason = isMalicious
    ? "Reason: Query contains patterns commonly associated with SQL injection."
    : "Reason: Query does not strongly match known SQL injection patterns.";

  return (
    <section className={`result-card ${isMalicious ? "danger" : "safe"}`}>
      <p className="result-banner">
        {isMalicious
          ? "Blocked: Potential SQL injection detected"
          : "Allowed: Query appears normal"}
      </p>
      <div className="result-grid">
        <div>
          <span className="result-label">Prediction</span>
          <strong>{result.prediction}</strong>
        </div>
        <div>
          <span className="result-label">Decision Score</span>
          <strong>{result.score.toFixed(4)}</strong>
          <small className="result-help">
            Higher scores indicate higher malicious risk.
          </small>
        </div>
        <div>
          <span className="result-label">Label</span>
          <strong>{result.label}</strong>
        </div>
        <div>
          <span className="result-label">Allowed</span>
          <strong>{String(result.allowed)}</strong>
        </div>
      </div>
      <p className="decision-rule">Decision Rule: score &gt;= -0.40 -&gt; Malicious</p>
      <p className="reason-text">{reason}</p>
    </section>
  );
}

export default function App() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyzeQuery() {
    if (!query.trim()) {
      setError("Please enter a query to analyze.");
      setResult(null);
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.detail || "Prediction request failed.");
      }

      setResult(data);
    } catch (requestError) {
      const isConnectionIssue =
        requestError instanceof TypeError ||
        String(requestError.message).includes("Failed to fetch");

      setError(
        isConnectionIssue
          ? "FastAPI server is not running. Start it with: python -m uvicorn app:app --reload"
          : requestError.message
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page-shell">
      <section className="app-card">
        <div className="hero">
          <span className="eyebrow">Security Demo</span>
          <h1>SQL Injection Detection</h1>
          <p>Real-time ML-powered SQL injection risk classification.</p>
        </div>

        <div className="examples">
          {EXAMPLE_QUERIES.map((exampleQuery) => (
            <button
              key={exampleQuery}
              type="button"
              className="example-chip"
              onClick={() => setQuery(exampleQuery)}
            >
              {exampleQuery}
            </button>
          ))}
        </div>

        <label className="input-label" htmlFor="query-input">
          Query Input
        </label>
        <textarea
          id="query-input"
          className="query-input"
          placeholder="' OR '1'='1"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          rows={7}
        />

        <button
          type="button"
          className="analyze-button"
          onClick={analyzeQuery}
          disabled={loading}
        >
          {loading ? "Analyzing..." : "Analyze"}
        </button>

        {error ? <div className="message error-message">{error}</div> : null}
        {loading ? (
          <div className="message loading-message">Processing request...</div>
        ) : null}
        <ResultCard result={result} />
        <p className="footer-note">
          This is a demo interface. In production, this system would run as a
          backend security layer integrated into applications.
        </p>
      </section>
    </main>
  );
}
