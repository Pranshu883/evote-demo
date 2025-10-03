// App.jsx - E-Voting Demo Component
import React, { useState, useEffect } from "react";
import "./VotingSimulation.css";

/*
E-Voting Demo (React + Web Crypto API)
- Standard RSA-OAEP encryption per vote
- Homomorphic-style masked vote vectors
- NPC vote generation (deterministic pseudo-random)
*/

// Utility functions for crypto operations
function abToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToAb(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function exportPublicKeyToPem(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const b64 = abToBase64(spki);
  return "-----BEGIN PUBLIC KEY-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----";
}

async function importAuthorityPubKeyFromSpkiBase64(b64) {
  const ab = base64ToAb(b64);
  return crypto.subtle.importKey("spki", ab, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

async function importAuthorityPrivKeyFromPkcs8Base64(b64) {
  const ab = base64ToAb(b64);
  return crypto.subtle.importKey("pkcs8", ab, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

// Icon components (simple SVG replacements for Lucide icons)
const IconShield = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

const IconUser = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
    <circle cx="12" cy="7" r="4"/>
  </svg>
);

const IconVote = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M9 11H5a2 2 0 0 0-2 2v3c0 1.1.9 2 2 2h4m6-6h4a2 2 0 0 1 2 2v3c0 1.1-.9 2-2 2h-4m-6 0V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2z"/>
  </svg>
);

const IconUsers = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
    <circle cx="9" cy="7" r="4"/>
    <path d="M22 21v-2a4 4 0 0 0-3-3.87"/>
    <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
  </svg>
);

const IconBarChart = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="12" x2="12" y1="20" y2="10"/>
    <line x1="18" x2="18" y1="20" y2="4"/>
    <line x1="6" x2="6" y1="20" y2="16"/>
  </svg>
);

const IconSearch = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8"/>
    <path d="M21 21l-4.35-4.35"/>
  </svg>
);

const IconEye = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
    <circle cx="12" cy="12" r="3"/>
  </svg>
);

const IconEyeOff = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
    <line x1="1" x2="23" y1="1" y2="23"/>
  </svg>
);

const IconKey = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="7.5" cy="15.5" r="5.5"/>
    <path d="M21 2l-9.6 9.6"/>
    <path d="M15.5 7.5l3 3L22 7l-3-3"/>
  </svg>
);

const IconLock = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);

const IconUnlock = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
  </svg>
);

const IconCheck = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="20,6 9,17 4,12"/>
  </svg>
);

const IconAlert = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" x2="12" y1="8" y2="12"/>
    <line x1="12" x2="12.01" y1="16" y2="16"/>
  </svg>
);

export default function App() {
  // State management
  const [authorityPubSpkiB64, setAuthorityPubSpkiB64] = useState(null);
  const [authorityPrivPkcs8B64, setAuthorityPrivPkcs8B64] = useState(null);
  const [voter, setVoter] = useState(null);
  const [bulletinBoard, setBulletinBoard] = useState([]);
  const [npcCount, setNpcCount] = useState(12);
  const [candidates] = useState(["Alice", "Bob", "Charlie"]);
  const [selected, setSelected] = useState(candidates[0]);
  const [receiptSearch, setReceiptSearch] = useState("");
  const [logs, setLogs] = useState([]);
  const [showTechnicalView, setShowTechnicalView] = useState(false);
  const [activeSection, setActiveSection] = useState("setup");

  // Logging helper
  function log(s) {
    setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${s}`, ...prev].slice(0, 50));
  }

  // Generate authority RSA keypair (dev-only)
  useEffect(() => {
    (async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
      );
      const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
      setAuthorityPubSpkiB64(abToBase64(spki));
      setAuthorityPrivPkcs8B64(abToBase64(pkcs8));
      log("Authority keypair generated (dev demo).");
    })();
    
  }, []);

  

  // Generate voter ECDSA keypair
  async function generateVoterIdentity(name = "Voter") {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const pubPem = await exportPublicKeyToPem(kp.publicKey);
    setVoter({ name, keyPair: kp, pubPem });
    log(`Generated identity '${name}'`);
  }

  // Sign ArrayBuffer
  async function signArrayBuffer(privateKey, arrayBuffer) {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, arrayBuffer);
    return abToBase64(sig);
  }

  // Verify signature
  async function verifySignature(publicKeyPem, signatureB64, ciphertextB64) {
    const pemBody = publicKeyPem.replace(/-----.*-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
    const pubKey = await crypto.subtle.importKey(
      "spki",
      der.buffer,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      base64ToAb(signatureB64),
      base64ToAb(ciphertextB64)
    );
  }

  // Encrypt with authority public key
  async function encryptWithAuthority(plaintext) {
    if (!authorityPubSpkiB64) throw new Error("Authority key not ready");
    const pub = await importAuthorityPubKeyFromSpkiBase64(authorityPubSpkiB64);
    const pt = new TextEncoder().encode(plaintext);
    const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, pt);
    return abToBase64(ct);
  }

  // Compute SHA-256 hex receipt
  async function computeReceiptHex(ciphertextB64, signatureB64) {
    const data = new TextEncoder().encode(ciphertextB64 + "|" + signatureB64);
    const h = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join("");
  }

  // Homomorphic voting helpers
  function voteToVector(choice) {
    const map = { "Alice": [1, 0, 0], "Bob": [0, 1, 0], "Charlie": [0, 0, 1] };
    return map[choice] || [0, 0, 0];
  }

  function addVectors(a, b) { 
    return a.map((v, i) => v + (b[i] || 0)); 
  }

  function subVectors(a, b) { 
    return a.map((v, i) => v - (b[i] || 0)); 
  }

  function zeroVector(len) { 
    return new Array(len).fill(0); 
  }

  function randomMaskVector(len) { 
    return Array.from({ length: len }, () => Math.floor(Math.random() * 1000)); 
  }

  function vecToStr(v) { 
    return JSON.stringify(v); 
  }

  function strToVec(s) { 
    try { return JSON.parse(s); } catch (e) { return null; } 
  }

  // Cast homomorphic vote
  async function castVoteHomomorphic(choice) {
  // Auto-generate new identity for each vote
  const tempKp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, 
    true, 
    ["sign", "verify"]
  );
  const tempPubPem = await exportPublicKeyToPem(tempKp.publicKey);
  const tempVoterName = voter ? `${voter.name}-${Math.random().toString(36).slice(2, 6)}` : `Voter-${Math.random().toString(36).slice(2, 6)}`;
  
  const voteVec = voteToVector(choice);
  const maskVec = randomMaskVector(voteVec.length);
  const maskedVec = addVectors(voteVec, maskVec);
  const maskedStr = vecToStr(maskedVec);
  const maskPlain = JSON.stringify({ mask: maskVec, voterName: tempVoterName });
  const encMask = await encryptWithAuthority(maskPlain);
  const sig = await signArrayBuffer(tempKp.privateKey, new TextEncoder().encode(maskedStr));
  const receipt = await computeReceiptHex(btoa(maskedStr), sig);
  const id = Math.random().toString(36).slice(2, 10);
  const ballot = { 
    id, 
    voterId: tempVoterName, 
    mode: "homomorphic", 
    masked: maskedStr, 
    encMask, 
    signature: sig, 
    publicKeyPem: tempPubPem, 
    receipt, 
    timestamp: new Date().toISOString() 
  };
  setBulletinBoard(prev => [ballot, ...prev]);
  log(`Cast homomorphic vote as ${tempVoterName} for ${choice}. Receipt: ${receipt.slice(0, 8)}`);
}

  // Verify receipt
  async function verifyReceiptHomomorphic(receipt) {
    const ballot = bulletinBoard.find(b => b.receipt === receipt || b.receipt.startsWith(receipt));
    if (!ballot) return { valid: false, reason: "Receipt not found" };

    const maskedB64 = btoa(ballot.masked);
    const expectedReceipt = await computeReceiptHex(maskedB64, ballot.signature);

    if (expectedReceipt !== ballot.receipt) return { valid: false, reason: "Receipt mismatch" };

    const sigOk = await verifySignature(ballot.publicKeyPem, ballot.signature, maskedB64);
    return { valid: sigOk, reason: sigOk ? "Valid" : "Signature invalid", ballot };
  }

  // Generate NPC homomorphic votes
  async function generateNPCsHomomorphic(n) {
    if (!authorityPubSpkiB64) { log("Authority not ready"); return; }
    for (let i = 0; i < n; i++) {
      const choice = candidates[Math.floor(Math.random() * candidates.length)];
      const npcName = `NPC-H-${Math.random().toString(36).slice(2, 6)}`;
      const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      const pubPem = await exportPublicKeyToPem(kp.publicKey);

      const voteVec = voteToVector(choice);
      const maskVec = randomMaskVector(voteVec.length);
      const maskedVec = addVectors(voteVec, maskVec);
      const maskedStr = vecToStr(maskedVec);

      const maskPlain = JSON.stringify({ mask: maskVec, voterName: npcName });
      const encMask = await encryptWithAuthority(maskPlain);
      const sig = await signArrayBuffer(kp.privateKey, new TextEncoder().encode(maskedStr));
      const receipt = await computeReceiptHex(btoa(maskedStr), sig);
      const id = Math.random().toString(36).slice(2, 10);

      const ballot = { 
        id, 
        voterId: npcName, 
        mode: "homomorphic", 
        masked: maskedStr, 
        encMask, 
        signature: sig, 
        publicKeyPem: pubPem, 
        receipt, 
        timestamp: new Date().toISOString() 
      };
      setBulletinBoard(prev => [ballot, ...prev]);
      
    }
    log(`Generated ${n} NPC homomorphic votes`);
  }

  // Tally homomorphic votes
  async function tallyHomomorphic() {
    const maskedVectors = bulletinBoard
      .filter(b => b.mode === "homomorphic")
      .map(b => ({ id: b.id, masked: strToVec(b.masked), encMask: b.encMask }));
    
    if (maskedVectors.length === 0) { 
      log("No homomorphic ballots found"); 
      return { tally: {}, details: [] }; 
    }
    
    const vecLen = maskedVectors[0].masked.length;
    let sumMasked = zeroVector(vecLen);
    maskedVectors.forEach(m => { sumMasked = addVectors(sumMasked, m.masked); });

    const priv = await importAuthorityPrivKeyFromPkcs8Base64(authorityPrivPkcs8B64);
    const decoder = new TextDecoder();
    let sumMasks = zeroVector(vecLen);
    
    for (const m of maskedVectors) {
      try {
        const ptab = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, base64ToAb(m.encMask));
        const parsed = JSON.parse(decoder.decode(ptab));
        sumMasks = addVectors(sumMasks, parsed.mask);
      } catch (e) { 
        log("Error decrypting mask for ballot " + m.id); 
      }
    }

    const tallyVec = subVectors(sumMasked, sumMasks);
    const tally = { 
      Alice: tallyVec[0] || 0, 
      Bob: tallyVec[1] || 0, 
      Charlie: tallyVec[2] || 0 
    };
    log("Homomorphic-style tally computed (dev).");
    return { tally, sumMasked, sumMasks };
  }

  // Decrypt all masks (for demonstration)
  async function decryptAllMasks() {
    if (!authorityPrivPkcs8B64) { log("Authority private key not ready"); return; }

    const priv = await importAuthorityPrivKeyFromPkcs8Base64(authorityPrivPkcs8B64);
    const decoder = new TextDecoder();
    const results = [];

    for (const b of bulletinBoard.filter(b => b.mode === "homomorphic")) {
      try {
        const decryptedMaskAb = await crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          priv,
          base64ToAb(b.encMask)
        );
        const decryptedMask = JSON.parse(decoder.decode(decryptedMaskAb)).mask;
        const maskedVec = strToVec(b.masked);
        const voteVec = subVectors(maskedVec, decryptedMask);

        results.push({
          voterId: b.voterId,
          maskedVec,
          mask: decryptedMask,
          voteVec
        });
      } catch (e) {
        log("Error decrypting mask for ballot " + b.id);
      }
    }

    log(`Decrypted ${results.length} homomorphic masks.`);
    return results;
  }

  // Component helpers
  const StatusIndicator = ({ status, children }) => (
    <div className={`status-indicator status-${status}`}>
      {status === "success" && <IconCheck />}
      {status === "error" && <IconAlert />}
      {status === "warning" && <IconAlert />}
      {status === "info" && <IconAlert />}
      <span>{children}</span>
    </div>
  );

  const Button = ({ children, variant = "primary", size = "md", className = "", disabled, ...props }) => (
    <button 
      className={`btn btn-${variant} ${size === "lg" ? "btn-lg" : ""} ${className}`}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="header-top">
            <div className="header-title">
              <h1>E-Voting Security Demo</h1>
              <p className="header-subtitle">Demonstrating cryptographic voting with homomorphic encryption</p>
            </div>
            <div className="header-actions">
              <Button 
                variant={showTechnicalView ? "primary" : "secondary"}
                onClick={() => setShowTechnicalView(!showTechnicalView)}
              >
                {showTechnicalView ? <IconEye /> : <IconEyeOff />}
                {showTechnicalView ? "Technical View" : "User View"}
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="main-container">
        {/* Navigation */}
        <nav className="nav-container">
          <div className="nav-tabs">
            {[
              { id: "setup", label: "Setup", icon: IconShield },
              { id: "vote", label: "Cast Vote", icon: IconVote },
              { id: "simulate", label: "Simulate", icon: IconUsers },
              { id: "results", label: "Results", icon: IconBarChart },
              { id: "verify", label: "Verify", icon: IconSearch }
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveSection(id)}
                className={`nav-tab ${activeSection === id ? 'active' : 'inactive'}`}
              >
                <Icon />
                {label}
              </button>
            ))}
          </div>
        </nav>

        <div className="content-grid">
          {/* Main Content */}
          <div className="main-content">
            {/* Setup Section */}
            {activeSection === "setup" && (
              <div className="main-content">
                <div className="card">
                  <div className="card-header">
                    <IconShield />
                    <h2 className="card-title">Election Authority Setup</h2>
                  </div>
                  <div className="card-content">
                    <StatusIndicator status={authorityPubSpkiB64 ? "success" : "warning"}>
                      Authority Keypair: {authorityPubSpkiB64 ? "Ready" : "Generating..."}
                    </StatusIndicator>
                    {showTechnicalView && authorityPubSpkiB64 && (
                      <div className="tech-panel tech-panel-blue">
                        <p><strong>RSA-2048 Public Key Generated</strong></p>
                        <p>Used for encrypting vote masks in homomorphic encryption</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="card">
                  <div className="card-header">
                    <IconUser />
                    <h2 className="card-title">Voter Identity</h2>
                  </div>
                  <div className="card-content">
                    {!voter ? (
                      <div>
                        <p>Generate your cryptographic identity to participate in the election.</p>
                        <Button onClick={() => generateVoterIdentity("You")}>
                          <IconKey />
                          Generate My Identity
                        </Button>
                      </div>
                    ) : (
                      <div>
                        <StatusIndicator status="success">
                          Identity Active: {voter.name}
                        </StatusIndicator>
                        {showTechnicalView && (
                          <details>
                            <summary>View ECDSA P-256 Public Key</summary>
                            <pre>{voter.pubPem}</pre>
                          </details>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Vote Section */}
            {activeSection === "vote" && (
              <div className="card">
                <div className="card-header">
                  <IconVote />
                  <h2 className="card-title">Cast Your Vote</h2>
                </div>
                <div className="card-content">
                  {!voter ? (
                    <StatusIndicator status="warning">
                      Please generate your identity first in the Setup section.
                    </StatusIndicator>
                  ) : (
                    <div>
                      <div className="form-group">
                        <label className="form-label">Choose your candidate:</label>
                        <div className="candidate-grid">
                          {candidates.map(candidate => (
                            <div key={candidate} className="candidate-option">
                              <input
                                type="radio"
                                name="candidate"
                                value={candidate}
                                checked={selected === candidate}
                                onChange={e => setSelected(e.target.value)}
                                className="candidate-input"
                                id={`candidate-${candidate}`}
                              />
                              <label htmlFor={`candidate-${candidate}`} className={`candidate-card ${selected === candidate ? 'selected' : ''}`}>
                                <div className="candidate-name">{candidate}</div>
                              </label>
                            </div>
                          ))}
                        </div>
                      </div>

                      <Button 
                        onClick={() => castVoteHomomorphic(selected)}
                        size="lg"
                      >
                        <IconLock />
                        Cast Homomorphic Vote
                      </Button>

                      {showTechnicalView && (
                        <div className="tech-panel tech-panel-blue">
                          <h3>Homomorphic Encryption Process:</h3>
                          <ul>
                            <li>• Vote converted to vector: {JSON.stringify(voteToVector(selected))}</li>
                            <li>• Random mask generated and added</li>
                            <li>• Mask encrypted with authority's public key</li>
                            <li>• Vote signed with your private key</li>
                            <li>• Receipt generated for verification</li>
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Simulate Section */}
            {activeSection === "simulate" && (
              <div className="card">
                <div className="card-header">
                  <IconUsers />
                  <h2 className="card-title">Simulate Additional Voters</h2>
                </div>
                <div className="card-content">
                  <div className="form-group">
                    <label className="form-label">Number of NPC voters to generate:</label>
                    <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                      <input
                        type="number"
                        value={npcCount}
                        onChange={e => setNpcCount(Number(e.target.value))}
                        className="form-input"
                        style={{ width: '100px' }}
                        min="1"
                        max="100"
                      />
                      <Button 
                        onClick={() => generateNPCsHomomorphic(npcCount)}
                        disabled={!authorityPubSpkiB64}
                      >
                        <IconUsers />
                        Generate NPC Votes
                      </Button>
                    </div>
                  </div>

                  {showTechnicalView && (
                    <div className="tech-panel tech-panel-orange">
                      <p>Each NPC generates its own ECDSA keypair and votes randomly for one of the candidates 
                         using the same homomorphic encryption process as real voters.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Results Section */}
            {activeSection === "results" && (
              <div className="main-content">
                <div className="card">
                  <div className="card-header">
                    <IconBarChart />
                    <h2 className="card-title">Election Results</h2>
                  </div>
                  <div className="card-content">
                    <Button 
                      onClick={async () => {
                        const { tally } = await tallyHomomorphic();
                        const total = Object.values(tally).reduce((a, b) => a + b, 0);
                        const results = `Election Results:\n\nAlice: ${tally.Alice} votes\nBob: ${tally.Bob} votes\nCharlie: ${tally.Charlie} votes\n\nTotal: ${total} votes`;
                        alert(results);
                      }}
                      disabled={bulletinBoard.filter(b => b.mode === "homomorphic").length === 0}
                    >
                      <IconBarChart />
                      Compute Tally
                    </Button>

                    {showTechnicalView && (
                      <Button 
                        onClick={async () => {
                          const results = await decryptAllMasks();
                          if (results.length === 0) { 
                            alert("No homomorphic votes found."); 
                            return; 
                          }

                          let msg = "Decrypted Vote Analysis:\n\n";
                          results.forEach(r => {
                            const choice = r.voteVec[0] ? "Alice" : r.voteVec[1] ? "Bob" : "Charlie";
                            msg += `${r.voterId}: ${choice}\n`;
                          });
                          alert(msg);
                        }}
                        variant="danger"
                      >
                        <IconUnlock />
                        Decrypt All Votes (Authority Only)
                      </Button>
                    )}

                    {showTechnicalView && (
                      <div className="tech-panel tech-panel-red">
                        <h3>⚠️ Privacy Warning:</h3>
                        <p>The "Decrypt All Votes" function demonstrates a critical vulnerability in e-voting systems. 
                           In a real system, this would compromise voter privacy and is exactly what homomorphic encryption aims to prevent.</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="card">
                  <h3 className="card-title">Bulletin Board</h3>
                  <div className="bulletin-board">
                    {bulletinBoard.length === 0 ? (
                      <p className="empty-state">No votes cast yet</p>
                    ) : (
                      bulletinBoard.map(ballot => (
                        <div key={ballot.id} className="ballot-item">
                          <div className="ballot-info">
                            <span className="ballot-voter">{ballot.voterId}</span>
                            <span className="ballot-receipt">
                              Receipt: {ballot.receipt.slice(0, 8)}...
                            </span>
                          </div>
                          <span className="ballot-timestamp">
                            {new Date(ballot.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Verify Section */}
            {activeSection === "verify" && (
              <div className="card">
                <div className="card-header">
                  <IconSearch />
                  <h2 className="card-title">Verify Vote Receipt</h2>
                </div>
                <div className="card-content">
                  <div className="form-group">
                    <label className="form-label">
                      Enter receipt (full hash or first 8 characters):
                    </label>
                    <div className="verify-form">
                      <div className="verify-input">
                        <input
                          type="text"
                          placeholder="e.g., a1b2c3d4..."
                          value={receiptSearch}
                          onChange={e => setReceiptSearch(e.target.value)}
                          className="form-input w-full"
                        />
                      </div>
                      <Button 
                        onClick={async () => {
                          if (!receiptSearch) return;
                          const result = await verifyReceiptHomomorphic(receiptSearch);
                          const status = result.valid ? "✅ Valid Receipt" : "❌ Invalid Receipt";
                          alert(`${status}\n\nReason: ${result.reason}`);
                        }}
                        disabled={!receiptSearch}
                      >
                        Verify
                      </Button>
                    </div>
                  </div>

                  {showTechnicalView && (
                    <div className="tech-panel tech-panel-indigo">
                      <h3>Receipt Verification Process:</h3>
                      <ul>
                        <li>• Finds ballot on bulletin board by receipt</li>
                        <li>• Recomputes receipt hash from stored data</li>
                        <li>• Verifies digital signature with voter's public key</li>
                        <li>• Confirms ballot integrity and authenticity</li>
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="sidebar">
            <div className="card">
              <div className="card-header">
                <IconAlert />
                <h3 className="card-title">System Status</h3>
              </div>
              <div className="card-content">
                <StatusIndicator status={authorityPubSpkiB64 ? "success" : "warning"}>
                  Authority: {authorityPubSpkiB64 ? "Ready" : "Initializing"}
                </StatusIndicator>
                <StatusIndicator status={voter ? "success" : "warning"}>
                  Voter: {voter ? "Registered" : "Not registered"}
                </StatusIndicator>
                <StatusIndicator status="info">
                  Votes Cast: {bulletinBoard.length}
                </StatusIndicator>
              </div>
            </div>

            <div className="card">
              <h3 className="card-title">Activity Log</h3>
              <div className="activity-log">
                {logs.length === 0 ? (
                  <p className="empty-state">No activity yet</p>
                ) : (
                  logs.slice(0, 10).map((log, i) => (
                    <div key={i} className="log-entry">
                      {log}
                    </div>
                  ))
                )}
              </div>
            </div>

            {showTechnicalView && (
              <div className="card">
                <h3 className="card-title">Technical Info</h3>
                <div style={{ fontSize: '0.75rem' }}>
                  <div><strong>Encryption:</strong> RSA-OAEP 2048-bit</div>
                  <div><strong>Signatures:</strong> ECDSA P-256</div>
                  <div><strong>Hashing:</strong> SHA-256</div>
                  <div><strong>Mode:</strong> Homomorphic (masked vectors)</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}