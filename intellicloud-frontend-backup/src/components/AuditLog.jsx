import React, { useEffect, useState} from "react";
import axios from "axios"

function AuditLog({ token }) {
    const [logs, setLogs] = useState([]);

    useEffect(() => {
        if (!token) return;
        axios   
            .get("http://localhost:5000/api/threats/audit-log", {
                headers: {
                    Authorization: `Bearer ${token}`,
            }
        })

        .then(res => setLogs(res.data))
        .catch(err => console.error("Error fetching audit logs:", err));
    }, [token]);

    return (
        <div>
            <h2 className="text-xl font-bold mb-4">My Audit Log</h2>
            {logs.length === 0 ? (
                <p>No actions found.</p>
            ) : (
                <table className="border w-full">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Target Threat ID</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {logs.map((log) => (
                            <tr key={log.log_id}>
                                <td>{log.action}</td>
                                <td>{log.target_id}</td>
                                <td>{new Date(log.timestamp).toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    )
}

export default AuditLog;