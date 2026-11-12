import type {
  AuditResponse, DocumentAnalysis, GatewayError, Metrics, Policy, ProcessResult, ProviderOption, UploadedDocument,
} from "./types";

const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }), ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error: GatewayError = { status: response.status, detail: body.detail ?? body };
    throw error;
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; detection_engine: string; backends: string[]; max_upload_bytes?: number }>("/health"),
  policies: () => request<Record<string, Policy>>("/v1/policies"),
  metrics: () => request<Metrics>("/v1/metrics"),
  audit: (limit = 50) => request<AuditResponse>(`/v1/audit?limit=${limit}`),
  auditDetail: (requestId: string) => request<Record<string, string>>(`/v1/audit/${encodeURIComponent(requestId)}`),
  providers: () => request<{ default: string; providers: ProviderOption[] }>("/v1/providers"),
  process: (body: { text: string; task: "summarize" | "extract"; purpose: string; doc_type?: string; instructions?: string; provider?: string }) =>
    request<ProcessResult>("/v1/process", { method: "POST", body: JSON.stringify(body) }),
  uploadDocument: (file: File, onProgress: (progress: number) => void) => new Promise<UploadedDocument>((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", `${API_URL}/v1/documents/upload`);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error("Network error while uploading the document."));
    request.timeout = 120000;
    request.ontimeout = () => reject(new Error("Document upload timed out. Try a smaller file or check the gateway."));
    request.onload = () => {
      let body: Record<string, unknown> = {};
      try { body = JSON.parse(request.responseText) as Record<string, unknown>; } catch { /* handled as an API error below */ }
      if (request.status >= 200 && request.status < 300) {
        resolve(body as unknown as UploadedDocument);
      } else {
        reject({ status: request.status, detail: body.detail ?? body } satisfies GatewayError);
      }
    };
    const form = new FormData();
    form.append("file", file);
    request.send(form);
  }),
  analyzeDocument: (documentId: string, token: string, purpose: string) =>
    request<DocumentAnalysis>("/v1/documents/analyze", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ document_id: documentId, purpose }),
    }),
  processDocument: (body: {
    document_id: string; task: "summarize" | "extract"; purpose: string; instructions?: string; provider?: string;
  }, token: string) => request<ProcessResult>("/v1/documents/process", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  }),
};

export function getApiUrl() {
  return API_URL;
}
