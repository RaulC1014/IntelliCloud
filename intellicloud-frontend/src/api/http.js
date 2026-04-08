import { API_ORIGIN, API_PREFIX } from "../config";

const origin = String(API_ORIGIN || "").replace(/\/+$/, "");
const prefix = String(API_PREFIX || "").replace(/^\/?/, "/").replace(/\/+$/, "");

function normalizePath(path = "") {
  return String(path).replace(/^\/+/, "");
}

export function apiUrl(path = "") {
  return `${origin}${prefix}/${normalizePath(path)}`;
}

export async function apiFetch(path, options = {}) {
  const res = await fetch(apiUrl(path), {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${text ? ` ${text}` : ""}`);
  }

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }

  return res.text();
}

export function buildSseUrl(path, params = {}) {
  const url = new URL(apiUrl(path));

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  });

  return url.toString();
}