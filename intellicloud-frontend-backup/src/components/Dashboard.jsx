import React from "react";
import { useAuth } from "../contexts/AuthContext";

function Dashboard() {
    const { role, email } = useAuth();

    return (
        <div style={{ padding: "20px" }}>
            <h1> Welcome to IntelliCloud</h1>
            <p>
                Logged in as <strong>{email}</strong> with role: <strong>{role}</strong>
            </p>

            {/* Sectino for all users */}
            <section style={{ marginTop: "20px" }}>
                <h2>Shared Tools</h2>
                <ul>
                    <li> View Threat Logs</li>
                    <li> Filter and Search Logs</li>
                </ul>
            </section>

            {/* Analyst and Admin roles */}
            {(role === "admin" || role === "analyst") && (
                <section style={{ marginTop: "20px" }}>
                    <h2> Analyst Tools </h2>
                    <ul>
                        <li> Threat Analysis </li>
                        <li> Behavior Monitoring </li>
                    </ul>
                </section>
            )}

            {/* Admin-Only section */}
            {role === "admin" && (
                <section style={{ marginTop: "20px" }}>
                    <h2> Admin Tools </h2>
                    <ul>
                        <li> Manage Users </li>
                        <li> View Audit Logs </li>
                        <li> System Configuration </li>
                    </ul>
                </section>
            )}
        </div>
    );
}

export default Dashboard;