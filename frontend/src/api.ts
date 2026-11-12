import type { AuditResponse, GatewayError, Metrics, Policy, ProcessResult } from "./types";

const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error: GatewayError = { status: response.status, detail: body.detail ?? body };
    throw error;
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; detection_engine: string; backends: string[] }>("/health"),
  policies: () => request<Record<string, Policy>>("/v1/policies"),
  metrics: () => request<Metrics>("/v1/metrics"),
  audit: (limit = 50) => request<AuditResponse>(`/v1/audit?limit=${limit}`),
  auditDetail: (requestId: string) => request<Record<string, string>>(`/v1/audit/${encodeURIComponent(requestId)}`),
  process: (body: { text: string; task: "summarize" | "extract"; purpose: string; doc_type?: string }) =>
    request<ProcessResult>("/v1/process", { method: "POST", body: JSON.stringify(body) }),
};

export function getApiUrl() {
  return API_URL;
}
