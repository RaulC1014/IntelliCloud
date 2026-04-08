import { apiFetch } from "./http";

export function agentStatus() {
  return apiFetch("agent/status", { method: "GET" });
}

export function agentStart() {
  return apiFetch("agent/start", { method: "POST" });
}

export function agentStop() {
  return apiFetch("agent/stop", { method: "POST" });
}