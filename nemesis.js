import React, { useState } from "react";

function App() {
  // State hooks to manage input fields and hold live API results
  const [targetUrl, setTargetUrl] = useState("");
  const [vulnType, setVulnType] = useState("SQL Injection (SQLi)");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleSimulate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      // Connects directly to your running FastAPI instance on port 8000
      const response = await fetch("http://127.0.0.1:8000/api/v1/simulate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target_url: targetUrl,
          vuln_type: vulnType,
        }),
      });

      if (!response.ok) {
        throw new Error(`Gateway returned terminal status code: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({
        target_url: targetUrl,
        vuln_type: vulnType,
        ai_analysis: `Gateway Connection Breakdown: ${error.message}. Ensure your Uvicorn backend is running!`,
        execution_payload: "N/A",
        status: "failed",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      padding: "40px", 
      fontFamily: "monospace", 
      color: "#00ff66", 
      minHeight: "100vh",
      backgroundImage: "linear-gradient(rgba(6, 10, 23, 0.55), rgba(6, 10, 23, 0.7)), url('/Art.jpg')",
      backgroundSize: "cover",
      backgroundPosition: "center center",
      backgroundAttachment: "fixed",
      boxSizing: "border-box"
    }}>
      
      {/* HEADER SECTION */}
      <header style={{ 
        borderBottom: "2px solid #00ff66", 
        paddingBottom: "20px", 
        marginBottom: "40px", 
        textAlign: "center",
        textShadow: "0 0 10px rgba(0, 255, 102, 0.3)"
      }}>
        <h1 style={{ 
          fontSize: "3.5rem", 
          margin: "0 0 10px 0", 
          color: "#ffffff", 
          letterSpacing: "6px",
          textShadow: "0 0 15px rgba(255, 255, 255, 0.5)"
        }}>
          NEMESIS
        </h1>
        <p style={{ fontSize: "1.2rem", color: "#00ff66", margin: "0 0 8px 0", fontWeight: "bold", letterSpacing: "1px" }}>
          Think Like an Attacker. Validate Like a Defender.
        </p>
        <p style={{ fontSize: "0.9rem", color: "#aaa", margin: 0, letterSpacing: "2px" }}>
          AI-POWERED SECURITY VALIDATION PLATFORM
        </p>
      </header>

      {/* TWO-COLUMN PANEL LAYOUT WITH SHARP GREEN BORDERS */}
      <main style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "40px" }}>
        
        {/* CONFIGURATION PANEL */}
        <section style={{ 
          border: "2px solid #00ff66", 
          padding: "25px", 
          backgroundColor: "rgba(17, 25, 48, 0.95)", 
          borderRadius: "8px",
          boxShadow: "0 4px 20px rgba(0, 0, 0, 0.8), 0 0 15px rgba(0, 255, 102, 0.15)"
        }}>
          <h2 style={{ color: "#ffffff", marginTop: "0", letterSpacing: "1px" }}>■ CONFIGURATION PANEL</h2>
          <form onSubmit={handleSimulate} style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
            <div>
              <label style={{ display: "block", marginBottom: "10px", fontWeight: "bold", fontSize: "0.9rem" }}>TARGET VECTOR URL:</label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://127.0.0.1:8000/mock-target/admin/dashboard"
                required
                style={{ width: "100%", padding: "14px", backgroundColor: "#060a17", color: "#00ff66", border: "1px solid #00ff66", borderRadius: "4px", boxSizing: "border-box", fontSize: "1rem" }}
              />
            </div>

            <div>
              <label style={{ display: "block", marginBottom: "10px", fontWeight: "bold", fontSize: "0.9rem" }}>THREAT VECTOR SELECTION:</label>
              <select
                value={vulnType}
                onChange={(e) => setVulnType(e.target.value)}
                style={{ width: "100%", padding: "14px", backgroundColor: "#060a17", color: "#00ff66", border: "1px solid #00ff66", borderRadius: "4px", boxSizing: "border-box", fontSize: "1rem", cursor: "pointer" }}
              >
                <option value="SQL Injection (SQLi)">SQL Injection (SQLi)</option>
                <option value="Broken Access Control">Broken Access Control</option>
                <option value="SSRF">SSRF</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{ 
                padding: "16px", 
                backgroundColor: "#00ff66", 
                color: "#060a17", 
                border: "none", 
                borderRadius: "4px", 
                fontWeight: "bold", 
                cursor: "pointer", 
                fontSize: "1rem",
                letterSpacing: "1px",
                boxShadow: "0 0 10px rgba(0, 255, 102, 0.4)",
                transition: "all 0.2s ease"
              }}
            >
              {loading ? "RUNNING SIMULATION ENGINE..." : "EXECUTE ANALYSIS & VALIDATION"}
            </button>
          </form>
        </section>

        {/* LIVE TRACKING TERMINAL */}
        <section style={{ 
          border: "2px solid #00ff66", 
          padding: "25px", 
          backgroundColor: "rgba(6, 10, 23, 0.95)", 
          borderRadius: "8px",
          boxShadow: "0 4px 20px rgba(0, 0, 0, 0.8), 0 0 15px rgba(0, 255, 102, 0.15)"
        }}>
          <h2 style={{ color: "#ffffff", marginTop: "0", letterSpacing: "1px" }}>■ LIVE TRACKING TERMINAL</h2>
          <div style={{ backgroundColor: "#000000", padding: "20px", minHeight: "335px", overflowY: "auto", border: "1px solid #00ff66", borderRadius: "4px" }}>
            {result ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                <div>
                  <span style={{ color: "#ffcc00", fontWeight: "bold" }}>[] TARGET_URL:</span> {result.target_url}
                </div>
                <div>
                  <span style={{ color: "#ffcc00", fontWeight: "bold" }}>[] VULN_TYPE:</span> {result.vuln_type}
                </div>
                <div>
                  <span style={{ color: "#ffcc00", fontWeight: "bold" }}>[] AI_ANALYSIS:</span>
                  <p style={{ color: "#ffffff", margin: "8px 0 0 0", lineHeight: "1.5", letterSpacing: "0.5px", whiteSpace: "pre-wrap" }}>{result.ai_analysis}</p>
                </div>
                <div>
                  <span style={{ color: "#ffcc00", fontWeight: "bold" }}>[] EXECUTION_PAYLOAD:</span> 
                  <code style={{ display: "block", backgroundColor: "#111", padding: "10px", marginTop: "8px", color: "#ff3366", border: "1px solid #333", borderRadius: "4px", overflowX: "auto" }}>{result.execution_payload}</code>
                </div>
                <div>
                  <span style={{ color: "#ffcc00", fontWeight: "bold" }}>[] VALIDATION_STATUS:</span>{" "}
                  <span style={{ color: result.status === "success" ? "#00ff66" : "#ff3333", fontWeight: "bold", textShadow: result.status === "success" ? "0 0 5px rgba(0,255,102,0.4)" : "none" }}>
                    {result.status ? result.status.toUpperCase() : "UNKNOWN"}
                  </span>
                </div>
              </div>
            ) : (
              <div style={{ color: "#555", textAlign: "center", paddingTop: "115px", lineHeight: "1.8", fontSize: "0.95rem" }}>
                {"// SOCKET LISTENER IDLE"} <br />
                Awaiting engine execution trigger parameters from configuration panel...
              </div>
            )}
          </div>          
        </section>
      </main>
    </div>
  );
}

export default App;