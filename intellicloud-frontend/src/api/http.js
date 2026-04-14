import { API_ORIGIN, API_PREFIX } from "../config";
import { getAuth } from "firebase/auth";

const origin = String(API_ORIGIN || "").replace(/\/+$/, "");
const prefix = String(API_PREFIX || "").replace(/^\/?/, "/").replace(/\/+$/, "");

function normalizePath(path = "") {
  return String(path).replace(/^\/+/, "");
}

export function apiUrl(path = "") {
  return `${origin}${prefix}/${normalizePath(path)}`;
}

async function getAuthToken() {
  try {
    const auth = getAuth();
    const user = auth.currentUser;
    if (!user) return null;
    return await user.getIdToken();
  } catch {
    return null;
  }
}

export async function apiFetch(path, options = {}) {
  // Attach Firebase token if user is logged in
  const token = await getAuthToken();

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(apiUrl(path), {
    ...options,
    headers,
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