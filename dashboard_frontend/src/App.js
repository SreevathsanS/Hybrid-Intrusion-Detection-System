import React, { useEffect, useState } from "react";
import {
  PieChart, Pie, Cell,
  LineChart, Line,
  CartesianGrid, XAxis, YAxis, Tooltip
} from "recharts";

const COLORS = ["#ff003c", "#ff2e63", "#ff6b6b", "#ff0000"];

function App() {
  const [data, setData] = useState({
    status: {},
    blockchain: {},
     live_attacks: [],
    recent_attacks: [],
    distribution: {},
    timeline: []
  });

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8001/ws/live");

    ws.onmessage = (event) => {
      setData(JSON.parse(event.data));
    };

    return () => ws.close();
  }, []);

  const pieData = Object.entries(data.distribution).map(
    ([key, value]) => ({ name: key, value })
  );

  return (
    <div>
      <h1 className="title">HYBRID ML IPS SOC</h1>

      <div className="grid">

        {/* System Status */}
        <div className="card">
          <h2>Status</h2>
          <p>System: {data.status.system_state}</p>
          <p>Blocked IPs: {data.status.blocked_ips?.length}</p>
          <h2>Blockchain</h2>
          <p>
            Status: {data.blockchain?.connected ? "CONNECTED" : "DISCONNECTED"}
          </p>
          <p>
            Block Number: {data.blockchain?.block_number ?? "-"}
          </p>
                  <h2>Blockchain Activity</h2>
        <p>Total Logged Attacks: {data.recent_attacks.length}</p>
        </div>
        {/* Distribution */}
        <div className="card">
          <h2>Attack Distribution</h2>
          <PieChart width={300} height={300}>
            <Pie
              data={pieData}
              dataKey="value"
              nameKey="name"
              outerRadius={100}
            >
              {pieData.map((entry, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </div>


      </div>

      {/* Timeline */}
      <div className="card">
        <h2>Attack Timeline</h2>
        <LineChart width={800} height={300} data={data.timeline}>
          <Line type="monotone" dataKey="count" stroke="#ff003c" />
          <CartesianGrid stroke="#333" />
          <XAxis dataKey="timestamp" />
          <YAxis />
          <Tooltip />
        </LineChart>
      </div>

      {/* Live Attack Feed */}
      <div className="card">
        <h2>Recent Attacks</h2>
        {data.recent_attacks.map((attack, index) => (
          <div key={index} style={{ marginBottom: "8px" }}>
            <div>
              {attack.timestamp} — {attack.src_ip} — {attack.attack_type}
            </div>

            {attack.tx_hash && (
              <div style={{ fontSize: "12px", color: "#ff6b6b" }}>
                TX:
                <a
                  href={`http://localhost:7545/tx/${attack.tx_hash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "#ff003c", marginLeft: "5px" }}
                >
                  {attack.tx_hash.substring(0, 20)}...
                </a>
              </div>
            )}
          </div>
        ))}
      </div>
      <div
      className={`card ${
        data.live_attacks && data.live_attacks.length > 0
          ? "live-alert"
          : "safe-alert"
      }`}
    >
      <h2>Live Attack Monitor</h2>

      {data.live_attacks && data.live_attacks.length > 0 ? (
        data.live_attacks.map((attack, index) => (
          <div key={index} style={{ marginBottom: "10px" }}>
            <strong>IP:</strong> {attack.src_ip} <br />
            <strong>Type:</strong> {attack.attack_type} <br />
            <strong>Packets:</strong> {attack.packet_count} <br />
            <strong>Status:</strong> {attack.status}
          </div>
        ))
      ) : (
        <div style={{ color: "#00ff88" }}>
          System Secure — No Active Attacks
        </div>
      )}
    </div>

    </div>
  );
}

export default App;