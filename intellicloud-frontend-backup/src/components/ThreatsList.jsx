import React, { useEffect, useState } from "react";
import { useMockData } from "../config";
import mockThreats from "../mock/threats";
import { useAuth } from "../contexts/AuthContext";
import axios from "axios";

function ThreatRow({ threat }) {
    return (
        <tr>
            <td>{threat.id}</td>
            <td>{threat.ip_address || threat.ip}</td>
            <td>{threat.threat_level}</td>
            <td>{threat.description}</td>
            <td>{new Date(threat.timestamp || threat.created_at).toLocaleString()}</td>
        </tr>
    );
}

function ThreatsList() {
    const { role, email } = useAuth();

    const [threats, setThreats] = useState([]);
    const [ipFilter, setIPFilter] = useState("");
    const [threatLevelFilter, setThreatLevelFilter] = useState("");

    useEffect(() => {
        if (useMockData) {

            console.log("Using mock threat data");

            let filtered = mockThreats;

            if (ipFilter) {
                filtered = filtered.filter((t) =>
                    (t.ip || t.ip_address).includes(ipFilter)
            );
        }

        if (threatLevelFilter) {
            filtered = filtered.filter(
                (t) => String(t.threat_level) === String(threatLevelFilter)
            );
        }

        setThreats(filtered);

        } else {

            let url = "http://localhost:5000/api/threats";
            const params = [];
            if (ipFilter) params.push(`ip=${encodeURIComponent(ipFilter)}`);
            if (threatLevelFilter) params.push(`threat_level=${encodeURIComponent(threatLevelFilter)}`);
            if (params.length > 0) url += `?${params.join("&")}`;
            axios
                .get(url)
                .then((response) => setThreats(response.data))
                .catch((error) => console.error("Error fetching threats:", error));
                
        }
    }, [ipFilter, threatLevelFilter]);

    const clearFilters = () => {
        setIPFilter("");
        setThreatLevelFilter("");
    };

    return (
        <div>
            <h2>Live Threats</h2>

            <p>
                Logged in as <strong>{email}</strong> with role: <strong>{role}</strong>
            </p>

            {/* Filter Inputs */}
            <div style={{marginBottom: "10px"}}>
                <input
                    type="text"
                    placeholder="Filter by IP"
                    value={ipFilter}
                    onChange={(e) => setIPFilter(e.target.value)}
                    style={{marginRight: "10px"}}
                />
                <select
                    value={threatLevelFilter}
                    onChange={(e) => setThreatLevelFilter(e.target.value)}
                    style={{ marginRight: "10px"}}
                >
                    <option value = "">All Threat Levels</option>
                    {[...Array(10)].map((_, i) => {
                        const level = i + 1;
                        return <option key={level} value={level}>{level}</option>;
                    })}
                </select>

                <button onClick={clearFilters}>Clear Filters</button>
            </div>

            {role === "admin" && (
                <div style={{ marginBottom: "10px "}}>
                    <button onClick = {() => alert("Performing admin action...")}>
                        Delete Selected Threats
                    </button>
                </div>
            )}
            {/* Threats Table */}
            {threats.length === 0 ? (
                <p> No threats found. </p>
            ) : (
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>IP Address</th>
                            <th>Level</th>
                            <th>Description</th>
                            <th>Timestamp</th>

                        </tr>
                    </thead>
                    <tbody>
                        {threats.map((threat) => (
                            <ThreatRow key={threat.id} threat = {threat} />
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

export default ThreatsList;