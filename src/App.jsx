import React, { useState } from "react";
import VotingSimulation from "./VotingSimulation";
import AttackLab from "./AttackLab";

export default function App() {
  const [mode, setMode] = useState("simulation"); // default mode

  return (
    <div>
      <header style={{ padding: "10px", textAlign: "center" }}>
        <button onClick={() => setMode("simulation")} style={{backgroundColor: "#60a5fa", margin: "0 10px" }}>
          Voting Simulation
        </button>
        <button onClick={() => setMode("attacklab")} style={{backgroundColor: "#60a5fa", margin: "0 10px" }}>
          Attack Lab
        </button>
      </header>

      <main>
        {mode === "simulation" ? <VotingSimulation /> : <AttackLab />}
      </main>
    </div>
  );
}