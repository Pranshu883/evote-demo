import React, { useEffect, useState } from "react";
import "./AttackLab.css";

/*
  Enhanced AttackLab.jsx
  - Better attack visualization and educational presentation
  - Clear before/after comparisons
  - Attack impact metrics and statistics
*/

function abToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToAb(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
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

/* ---------- Vector helpers ---------- */
function voteToVector(choice) {
  const map = { "Alice": [1, 0, 0], "Bob": [0, 1, 0], "Charlie": [0, 0, 1] };
  return map[choice] || [0, 0, 0];
}
function addVectors(a, b) { return a.map((v, i) => v + (b?.[i] || 0)); }
function subVectors(a, b) { return a.map((v, i) => v - (b?.[i] || 0)); }
function zeroVector(len) { return new Array(len).fill(0); }
function vecToStr(v) { return JSON.stringify(v); }
function strToVec(s) { try { return JSON.parse(s); } catch { return null; } }

export default function AttackLab() {
  // Keys & state
  const [authorityPubSpkiB64, setAuthorityPubSpkiB64] = useState(null);
  const [authorityPrivPkcs8B64, setAuthorityPrivPkcs8B64] = useState(null);

  const [voter, setVoter] = useState(null);
  const [bulletinBoard, setBulletinBoard] = useState([]);
  const [selected, setSelected] = useState("Alice");
  const [npcCount, setNpcCount] = useState(8);
  const [logs, setLogs] = useState([]);
  const [receiptSearch, setReceiptSearch] = useState("");

  // Attack toggles
  const [attacks, setAttacks] = useState({
    malware: false,
    weakRandom: false,
    insider: false,
    dos: false,
  });

  // Attack statistics & visualization
  const [attackStats, setAttackStats] = useState({
    malwareFlips: 0,
    weakMasksGenerated: 0,
    insiderReveals: 0,
    totalVotes: 0,
    compromisedVotes: 0,
    dosBlocked: 0
  });

  const [revealedVotes, setRevealedVotes] = useState([]);
  const [showTally, setShowTally] = useState(false);
  const [currentTally, setCurrentTally] = useState(null);

  const candidates = ["Alice", "Bob", "Charlie"];

  function appendLog(msg) {
    const line = `[${new Date().toLocaleTimeString()}] ${msg}`;
    setLogs(prev => [line, ...prev].slice(0, 200));
  }

  // Authority key generation
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
      appendLog("✓ Authority RSA-OAEP keypair generated");
    })();
  }, []);

  async function generateVoterIdentity(name = "You") {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const pubPem = await exportPublicKeyToPem(kp.publicKey);
    setVoter({ name, keyPair: kp, pubPem });
    appendLog(`✓ Generated voter identity '${name}'`);
  }

  async function signArrayBuffer(privateKey, arrayBuffer) {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, arrayBuffer);
    return abToBase64(sig);
  }

  async function verifySignature(publicKeyPem, signatureB64, messageB64) {
    const pemBody = publicKeyPem.replace(/-----.*-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
    const pubKey = await crypto.subtle.importKey("spki", der.buffer, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, base64ToAb(signatureB64), base64ToAb(messageB64));
  }

  async function encryptWithAuthority(plaintext) {
    if (!authorityPubSpkiB64) throw new Error("Authority public key not ready");
    const pub = await importAuthorityPubKeyFromSpkiBase64(authorityPubSpkiB64);
    const pt = new TextEncoder().encode(plaintext);
    const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, pt);
    return abToBase64(ct);
  }

  async function computeReceiptHex(ciphertextB64, signatureB64) {
    const data = new TextEncoder().encode(ciphertextB64 + "|" + signatureB64);
    const h = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join("");
  }

  function randomMaskVector(len) {
    if (attacks.weakRandom) {
      const arr = [];
      let s = 0xBEEF1234;
      for (let i = 0; i < len; i++) {
        s = (1664525 * s + 1013904223) >>> 0;
        arr.push((s >>> (i % 24)) & 0xFF % 10);
      }
      setAttackStats(prev => ({ ...prev, weakMasksGenerated: prev.weakMasksGenerated + 1 }));
      return arr;
    }
    return Array.from({ length: len }, () => Math.floor(Math.random() * 1000));
  }

  async function applyClientSideAttacks({ voteVec, maskVec, maskedVec, voterName }) {
    let finalVote = voteVec.slice();
    let finalMask = maskVec.slice();
    let finalMasked = maskedVec.slice();

    if (attacks.malware) {
      const oldIndex = finalVote.findIndex(x => x === 1);
      const flipIndex = (oldIndex + 1) % finalVote.length;
      const corrupted = finalVote.map((_, i) => (i === flipIndex ? 1 : 0));
      finalVote = corrupted;
      finalMasked = addVectors(finalVote, finalMask);

      setAttackStats(prev => ({
        ...prev,
        malwareFlips: prev.malwareFlips + 1,
        compromisedVotes: prev.compromisedVotes + 1
      }));

      appendLog(`⚠️ MALWARE: Vote flipped for ${voterName}`);
    }

    return { voteVec: finalVote, maskVec: finalMask, maskedVec: finalMasked };
  }

  async function castVoteHomomorphic(choice) {

    if (attacks.dos) {
      setAttackStats(prev => ({ ...prev, dosBlocked: prev.dosBlocked + 1 }));
      appendLog("❌ DoS ATTACK: Server unavailable - vote blocked");
      alert("⚠️ Server Unavailable\n\nThe voting server is currently unreachable. Please try again later.\n\n(This simulates a Denial of Service attack)");
      return;
    }
    if (!voter) { appendLog("❌ No voter identity"); return; }
    if (!authorityPubSpkiB64) { appendLog("❌ Authority key not ready"); return; }

    const voteVec = voteToVector(choice);
    const maskVec = randomMaskVector(voteVec.length);
    let maskedVec = addVectors(voteVec, maskVec);

    const attacked = await applyClientSideAttacks({ voteVec, maskVec, maskedVec, voterName: voter.name });
    const finalVote = attacked.voteVec;
    const finalMask = attacked.maskVec;
    const finalMasked = attacked.maskedVec;

    const maskedStr = vecToStr(finalMasked);
    const encMask = await encryptWithAuthority(JSON.stringify({ mask: finalMask, voterName: voter.name }));
    const sig = await signArrayBuffer(voter.keyPair.privateKey, new TextEncoder().encode(maskedStr));
    const receipt = await computeReceiptHex(btoa(maskedStr), sig);
    const id = Math.random().toString(36).slice(2, 10);

    const ballot = {
      id,
      voterId: voter.name,
      mode: "homomorphic",
      masked: maskedStr,
      encMask,
      signature: sig,
      publicKeyPem: voter.pubPem,
      receipt,
      timestamp: new Date().toISOString(),
      attackedBy: attacks.malware ? 'malware' : null,
      weakMask: attacks.weakRandom
    };

    setBulletinBoard(prev => [ballot, ...prev]);
    setAttackStats(prev => ({ ...prev, totalVotes: prev.totalVotes + 1 }));
    appendLog(`✓ Vote cast: ${choice} → receipt ${receipt.slice(0, 10)}...`);
  }

  async function generateNPCsHomomorphic(n = 8) {
    if (!authorityPubSpkiB64) { appendLog("❌ Authority key not ready"); return; }

    for (let i = 0; i < n; i++) {
      const choice = candidates[Math.floor(Math.random() * candidates.length)];
      const npcName = `NPC-${Math.random().toString(36).slice(2, 6)}`;
      const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      const pubPem = await exportPublicKeyToPem(kp.publicKey);

      const voteVec = voteToVector(choice);
      const maskVec = randomMaskVector(voteVec.length);
      let maskedVec = addVectors(voteVec, maskVec);

      const attacked = await applyClientSideAttacks({ voteVec, maskVec, maskedVec, voterName: npcName });
      const finalVote = attacked.voteVec;
      const finalMask = attacked.maskVec;
      const finalMasked = attacked.maskedVec;

      const maskedStr = vecToStr(finalMasked);
      const encMask = await encryptWithAuthority(JSON.stringify({ mask: finalMask, voterName: npcName }));
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
        timestamp: new Date().toISOString(),
        attackedBy: attacks.malware ? 'malware' : null,
        weakMask: attacks.weakRandom
      };

      setBulletinBoard(prev => [ballot, ...prev]);
      setAttackStats(prev => ({ ...prev, totalVotes: prev.totalVotes + 1 }));
    }
    appendLog(`✓ Generated ${n} NPC votes`);
  }

  async function tallyHomomorphic() {
    const maskedVectors = bulletinBoard.filter(b => b.mode === "homomorphic")
      .map(b => ({ id: b.id, masked: strToVec(b.masked), encMask: b.encMask }));

    if (maskedVectors.length === 0) {
      appendLog("❌ No ballots to tally");
      alert("No homomorphic ballots found.");
      return;
    }

    const vecLen = maskedVectors[0].masked.length;
    let sumMasked = zeroVector(vecLen);
    for (const m of maskedVectors) sumMasked = addVectors(sumMasked, m.masked);

    const priv = await importAuthorityPrivKeyFromPkcs8Base64(authorityPrivPkcs8B64);
    const decoder = new TextDecoder();
    let sumMasks = zeroVector(vecLen);

    for (const m of maskedVectors) {
      try {
        const ptab = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, base64ToAb(m.encMask));
        const parsed = JSON.parse(decoder.decode(ptab));
        sumMasks = addVectors(sumMasks, parsed.mask);
      } catch (e) {
        appendLog(`❌ Error decrypting mask for ${m.id}`);
      }
    }

    const tallyVec = subVectors(sumMasked, sumMasks);
    const tally = { Alice: tallyVec[0] || 0, Bob: tallyVec[1] || 0, Charlie: tallyVec[2] || 0 };

    setCurrentTally(tally);
    setShowTally(true);

    appendLog(`✓ TALLY: Alice=${tally.Alice}, Bob=${tally.Bob}, Charlie=${tally.Charlie}`);

    return { tally, sumMasked, sumMasks };
  }

  async function decryptAllMasksAndReveal() {
    if (!attacks.insider) {
      appendLog("❌ Insider attack not enabled");
      alert("Enable 'Insider' toggle to demonstrate privacy breach");
      return;
    }

    if (!authorityPrivPkcs8B64) { appendLog("❌ Authority key not ready"); return; }

    const priv = await importAuthorityPrivKeyFromPkcs8Base64(authorityPrivPkcs8B64);
    const decoder = new TextDecoder();
    const results = [];

    for (const b of bulletinBoard.filter(b => b.mode === "homomorphic")) {
      try {
        const ptab = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, base64ToAb(b.encMask));
        const parsed = JSON.parse(decoder.decode(ptab));
        const mask = parsed.mask;
        const masked = strToVec(b.masked);
        const vote = subVectors(masked, mask);

        const choiceIndex = vote.findIndex(v => v === 1);
        const choice = candidates[choiceIndex] || 'Unknown';

        results.push({
          id: b.id,
          voterId: b.voterId,
          vote,
          choice,
          wasAttacked: b.attackedBy ? true : false
        });
      } catch (e) {
        results.push({ id: b.id, voterId: b.voterId, vote: null, error: true });
      }
    }

    setRevealedVotes(results);
    setAttackStats(prev => ({ ...prev, insiderReveals: prev.insiderReveals + 1 }));
    appendLog(`⚠️ INSIDER ATTACK: Revealed ${results.length} individual votes (privacy breached!)`);

    return results;
  }

  async function verifyReceipt(receiptPrefix) {
    const b = bulletinBoard.find(x => x.receipt === receiptPrefix || x.receipt.startsWith(receiptPrefix));
    if (!b) return { found: false };

    const maskedB64 = btoa(b.masked);
    const recomputed = await computeReceiptHex(maskedB64, b.signature);
    if (recomputed !== b.receipt) return { found: true, valid: false, reason: "receipt mismatch" };

    const sigOk = await verifySignature(b.publicKeyPem, b.signature, maskedB64);
    return { found: true, valid: sigOk, reason: sigOk ? "Valid ✓" : "Invalid signature", ballot: b };
  }

  function resetAttackLab() {
    setBulletinBoard([]);
    setAttackStats({
      malwareFlips: 0,
      weakMasksGenerated: 0,
      insiderReveals: 0,
      totalVotes: 0,
      compromisedVotes: 0,
      dosBlocked: 0  
    });
    setRevealedVotes([]);
    setLogs([]);
    setShowTally(false);
    setCurrentTally(null);
    appendLog("✓ Attack Lab reset");
  }

  const attackDescriptions = {
    malware: {
      title: "Client-Side Malware Attack",
      icon: "🦠",
      description: "Compromised voting device silently flips votes before they're encrypted and signed. The voter sees their intended choice, but a different vote is actually cast.",
      impact: "Breaks cast-as-intended verification. Voter receipt shows tampered vote as valid.",
      defense: "Requires secure boot, trusted hardware, or independent vote verification devices.",
      severity: "high"
    },
    weakRandom: {
      title: "Weak Random Number Generator",
      icon: "🎲",
      description: "Predictable random number generation allows masks to be guessed, potentially exposing individual votes even with homomorphic encryption.",
      impact: "Compromises privacy. Attackers may deduce votes from patterns in masked values.",
      defense: "Use cryptographically secure random number generators (CSPRNG) with proper entropy.",
      severity: "medium"
    },
    insider: {
      title: "Insider Attack (Authority Misuse)",
      icon: "🔓",
      description: "Election authority with decryption keys can decrypt individual vote masks, revealing who voted for whom despite encryption.",
      impact: "Complete privacy breach. Authority can see all individual votes, enabling coercion or manipulation.",
      defense: "Use threshold cryptography (split keys among multiple authorities) or zero-knowledge proofs.",
      severity: "critical"
    },
    dos: {
      title: "Denial of Service (DoS) Attack",
      icon: "🌐",
      description: "Attackers flood the voting server with fake traffic or exploit vulnerabilities to make it unavailable. Even with perfect cryptography, voters cannot cast ballots if they can't reach the server.",
      impact: "Prevents legitimate voters from participating. Can disenfranchise voters and invalidate election results.",
      defense: "DDoS protection, rate limiting, redundant servers, distributed infrastructure, offline backup voting methods.",
      severity: "critical"
    }

  };

  return (
    <div className="attack-lab-container">
      <div className="attack-lab-wrapper">
        <header className="lab-header">
          <h1 className="lab-title">🛡️ Attack Lab</h1>
          <p className="lab-subtitle">Interactive demonstration of e-voting security vulnerabilities</p>
        </header>

        {/* Attack Statistics Dashboard */}
        <section className="stats-section">
          <h2 className="section-title">📊 Attack Statistics</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{attackStats.totalVotes}</div>
              <div className="stat-label">Total Votes Cast</div>
            </div>
            <div className="stat-card stat-danger">
              <div className="stat-value">{attackStats.compromisedVotes}</div>
              <div className="stat-label">Compromised Votes</div>
            </div>
            <div className="stat-card stat-warning">
              <div className="stat-value">{attackStats.malwareFlips}</div>
              <div className="stat-label">Malware Flips</div>
            </div>
            <div className="stat-card stat-info">
              <div className="stat-value">{attackStats.weakMasksGenerated}</div>
              <div className="stat-label">Weak Masks</div>
            </div>
            <div className="stat-card stat-critical">
              <div className="stat-value">{attackStats.insiderReveals}</div>
              <div className="stat-label">Insider Breaches</div>
            </div>
            <div className="stat-card stat-critical">
              <div className="stat-value">{attackStats.dosBlocked}</div>
              <div className="stat-label">DoS Blocked Votes</div>
            </div>
          </div>
        </section>

        {/* Attack Configuration */}
        <section className="attack-config-section">
          <h2 className="section-title">⚠️ Attack Configuration</h2>

          <div className="attack-cards-grid">
            {Object.entries(attackDescriptions).map(([key, info]) => (
              <div
                key={key}
                className={`attack-card ${attacks[key] ? 'attack-active' : ''} severity-${info.severity}`}
              >
                <div className="attack-card-header">
                  <input
                    type="checkbox"
                    id={key}
                    checked={attacks[key]}
                    onChange={e => setAttacks(prev => ({ ...prev, [key]: e.target.checked }))}
                    className="attack-checkbox"
                  />
                  <label htmlFor={key} className="attack-title">
                    <span className="attack-icon">{info.icon}</span>
                    {info.title}
                  </label>
                </div>
                <p className="attack-description">{info.description}</p>
                <div className="attack-impact">
                  <strong>Impact:</strong> {info.impact}
                </div>
                <div className="attack-defense">
                  <strong>Defense:</strong> {info.defense}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Quick Actions */}
        <section className="actions-section">
          <h2 className="section-title">🚀 Quick Actions</h2>

          <div className="actions-grid">
            {!voter && (
              <button
                onClick={() => generateVoterIdentity("You")}
                className="btn btn-primary"
              >
                🆔 Generate Identity
              </button>
            )}

            {voter && (
              <>
                <div className="voter-info">
                  <span className="voter-label">Active Voter:</span>
                  <span className="voter-name">{voter.name}</span>
                </div>

                <select
                  value={selected}
                  onChange={e => setSelected(e.target.value)}
                  className="candidate-select"
                >
                  {candidates.map(c => <option key={c} value={c}>{c}</option>)}
                </select>

                <button
                  onClick={() => castVoteHomomorphic(selected)}
                  className="btn btn-primary"
                >
                  🗳️ Cast Vote
                </button>
              </>
            )}

            <input
              type="number"
              value={npcCount}
              onChange={e => setNpcCount(Number(e.target.value))}
              min="1"
              max="50"
              className="npc-count-input"
            />

            <button
              onClick={() => generateNPCsHomomorphic(npcCount)}
              className="btn btn-secondary"
            >
              👥 Generate {npcCount} NPCs
            </button>

            <button
              onClick={() => tallyHomomorphic()}
              className="btn btn-success"
              disabled={bulletinBoard.length === 0}
            >
              📊 Compute Tally
            </button>

            <button
              onClick={() => decryptAllMasksAndReveal()}
              className="btn btn-danger"
              disabled={!attacks.insider}
            >
              🔓 Insider Reveal
            </button>

            <button
              onClick={() => resetAttackLab()}
              className="btn btn-reset"
            >
              🔄 Reset Lab
            </button>
          </div>
        </section>

        {/* Tally Results */}
        {showTally && currentTally && (
          <section className="tally-section">
            <h2 className="section-title">📊 Election Results</h2>
            <div className="tally-results">
              {Object.entries(currentTally).map(([candidate, votes]) => (
                <div key={candidate} className="tally-item">
                  <span className="tally-candidate">{candidate}</span>
                  <div className="tally-bar-container">
                    <div
                      className="tally-bar"
                      style={{
                        width: `${(votes / Math.max(...Object.values(currentTally))) * 100}%`
                      }}
                    ></div>
                    <span className="tally-count">{votes}</span>
                  </div>
                </div>
              ))}
            </div>
            {attackStats.compromisedVotes > 0 && (
              <div className="tally-warning">
                ⚠️ WARNING: {attackStats.compromisedVotes} votes were compromised by attacks!
              </div>
            )}
          </section>
        )}

        {/* Revealed Votes */}
        {revealedVotes.length > 0 && (
          <section className="revealed-votes-section">
            <h2 className="section-title">🚨 Insider Attack: Revealed Individual Votes</h2>
            <div className="revealed-votes-warning">
              This demonstrates why authority trustworthiness is critical. All voter privacy has been compromised!
            </div>
            <div className="revealed-votes-list">
              {revealedVotes.map((rv, idx) => (
                <div key={idx} className={`revealed-vote-item ${rv.wasAttacked ? 'vote-attacked' : ''}`}>
                  <span className="revealed-voter">{rv.voterId}</span>
                  <span className="revealed-arrow">→</span>
                  <span className="revealed-choice">{rv.choice}</span>
                  {rv.wasAttacked && <span className="revealed-badge">Malware Flipped</span>}
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Receipt Verification */}
        <section className="verification-section">
          <h2 className="section-title">🔍 Receipt Verification</h2>
          <div className="verification-panel">
            <input
              placeholder="Paste receipt or prefix..."
              value={receiptSearch}
              onChange={e => setReceiptSearch(e.target.value)}
              className="receipt-input"
            />
            <button
              className="btn btn-primary"
              onClick={async () => {
                if (!receiptSearch) return;
                const res = await verifyReceipt(receiptSearch.trim());
                if (!res.found) {
                  alert("❌ Receipt not found on bulletin board");
                } else {
                  alert(`${res.valid ? '✅' : '❌'} Verification Result\n\nStatus: ${res.reason}\n\nVoter: ${res.ballot.voterId}\nTimestamp: ${new Date(res.ballot.timestamp).toLocaleString()}`);
                }
              }}
            >
              Verify Receipt
            </button>
          </div>
        </section>

        {/* Bulletin Board */}
        <section className="bulletin-section">
          <h2 className="section-title">📋 Bulletin Board ({bulletinBoard.length} ballots)</h2>
          <div className="bulletin-board">
            {bulletinBoard.length === 0 ? (
              <div className="bulletin-empty">No ballots cast yet. Start voting to see them appear here.</div>
            ) : (
              bulletinBoard.map(b => (
                <div key={b.id} className={`ballot-item ${b.attackedBy ? 'ballot-compromised' : ''}`}>
                  <div className="ballot-header">
                    <span className="ballot-voter">{b.voterId}</span>
                    <span className="ballot-time">{new Date(b.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="ballot-receipt">
                    <span className="receipt-label">Receipt:</span>
                    <code className="receipt-code">{b.receipt.slice(0, 16)}...</code>
                  </div>
                  {b.attackedBy && (
                    <div className="ballot-badge">🦠 Malware Compromised</div>
                  )}
                  {b.weakMask && (
                    <div className="ballot-badge ballot-badge-warning">🎲 Weak RNG</div>
                  )}
                </div>
              ))
            )}
          </div>
        </section>

        {/* Activity Logs */}
        <section className="logs-section">
          <h2 className="section-title">📝 Activity Logs</h2>
          <div className="logs-container">
            {logs.length === 0 ? (
              <div className="logs-empty">No activity yet...</div>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="log-entry">{log}</div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}