import { apiFetch } from "./http";

export function fetchAssets() {
  return apiFetch("assets");
}

export function createAsset(payload) {
  return apiFetch("assets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function updateAsset(id, payload) {
  return apiFetch(`assets/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function deleteAsset(id) {
  return apiFetch(`assets/${id}`, {
    method: "DELETE",
  });
}