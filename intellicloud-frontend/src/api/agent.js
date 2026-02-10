
import { API_BASE_URL } from "../config";

const base = (API_BASE_URL || "").replace(/\/+$/, ""); 

async function req(path, options = {}) {
  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return res.json().catch(() => ({}));
}

export const agentStatus = () => req("/api/agent/status", { method: "GET" });
export const agentStart  = () => req("/api/agent/start",  { method: "POST" });
export const agentStop   = () => req("/api/agent/stop",   { method: "POST" });