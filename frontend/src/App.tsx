import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ClipboardEvent as ReactClipboardEvent, type ReactNode } from "react";
import { AnimatePresence, motion, MotionConfig } from "framer-motion";
import {
  Activity, AlertTriangle, ArrowDownToLine, Check, CheckCircle2, ChevronDown, ChevronRight,
  CircleHelp, Clipboard, Clock3, CloudUpload, Download, FileCheck2, FileText, Fingerprint, Image as ImageIcon,
  LockKeyholeOpen, Network, RotateCw, Shield, ShieldAlert, ShieldCheck, Sparkles, X,
} from "lucide-react";
import { api, getApiUrl } from "./api";
import { entityColors, fallbackPolicies, metricsFallback, samples } from "./data";
import type {
  AuditRecord, DocumentAnalysis, Entity, GatewayError, Metrics, Policy, ProcessResult, ProviderOption, UploadedDocument,
} from "./types";

const MetricsTab = lazy(() => import("./MetricsTab"));

type GatewayFailure = { kind: "blocked" | "leak" | "unavailable"; message: string; requestId?: string; labels?: string[] };
type Span = { start: number; end: number; label: string; placeholder: string; value: string };
type MockEntity = Entity & { value: string };

const flowSteps = [
  { label: "Document", icon: FileText },
  { label: "Detection", icon: Fingerprint },
  { label: "Masking", icon: ShieldCheck },
  { label: "AI", icon: Network },
  { label: "Restoration", icon: RotateCw },
];

function isGatewayError(error: unknown): error is GatewayError {
  return typeof error === "object" && error !== null && "status" in error;
}

function errorDetail(error: GatewayError): Record<string, unknown> {
  return typeof error.detail === "object" && error.detail !== null ? error.detail as Record<string, unknown> : {};
}

function parseJson<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try { return JSON.parse(value) as T; } catch { return fallback; }
}

function entityClass(label: string) {
  return entityColors[label] ?? "entity-default";
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getSpans(text: string, entities: Entity[]): Span[] {
  return entities
    .filter((entity) => entity.pass === 1 && entity.start >= 0 && entity.end <= text.length)
    .map((entity) => ({
      start: entity.start,
      end: entity.end,
      label: entity.label,
      placeholder: entity.placeholder,
      value: text.slice(entity.start, entity.end),
    }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
}

function renderMarkedText(text: string, spans: Span[], active: string | null, onHover: (placeholder: string | null) => void) {
  const nodes: ReactNode[] = [];
  let position = 0;
  spans.forEach((span, index) => {
    if (span.start < position) return;
    if (span.start > position) nodes.push(text.slice(position, span.start));
    nodes.push(
      <mark
        key={`${span.placeholder}-${index}`}
        className={`marked ${entityClass(span.label)} ${active === span.placeholder ? "is-linked" : ""}`}
        title={`${span.label} · ${span.placeholder}`}
        onMouseEnter={() => onHover(span.placeholder)}
        onMouseLeave={() => onHover(null)}
      >
        {text.slice(span.start, span.end)}
        <span className="mark-label">{span.label}</span>
      </mark>,
    );
    position = span.end;
  });
  if (position < text.length) nodes.push(text.slice(position));
  return nodes;
}

function renderPlaceholders(text: string, spans: Span[], active: string | null, onHover: (placeholder: string | null) => void) {
  const matches = [...text.matchAll(/<[A-Z_]+_\d+>|\[(?:[A-Z_]+_\d+|REDACTED_[A-Z_]+)\]/g)];
  if (!matches.length) return text;
  const nodes: ReactNode[] = [];
  let position = 0;
  matches.forEach((match, index) => {
    const token = match[0];
    const start = match.index ?? 0;
    if (start > position) nodes.push(text.slice(position, start));
    const entity = spans.find((span) => span.placeholder === token);
    const label = entity?.label ?? token.replace(/[<>\[\]]/g, "").replace(/_\d+$/, "").replace("REDACTED_", "");
    nodes.push(
      <span
        key={`${token}-${index}`}
        className={`token-pill ${entityClass(label)} ${active === token ? "is-linked" : ""}`}
        onMouseEnter={() => onHover(token)}
        onMouseLeave={() => onHover(null)}
      >
        {token}
      </span>,
    );
    position = start + token.length;
  });
  if (position < text.length) nodes.push(text.slice(position));
  return nodes;
}

function renderRestored(text: string, spans: Span[], active: string | null, onHover: (placeholder: string | null) => void) {
  const ranges: Array<{ start: number; end: number; span: Span }> = [];
  const values = [...new Set(spans.map((span) => span.value))].sort((a, b) => b.length - a.length);
  values.forEach((value) => {
    let from = 0;
    while (value && from < text.length) {
      const start = text.indexOf(value, from);
      if (start < 0) break;
      const span = spans.find((candidate) => candidate.value === value);
      if (span) ranges.push({ start, end: start + value.length, span });
      from = start + value.length;
    }
  });
  ranges.sort((a, b) => a.start - b.start || b.end - a.end);
  const nodes: ReactNode[] = [];
  let position = 0;
  ranges.forEach(({ start, end, span }, index) => {
    if (start < position) return;
    if (start > position) nodes.push(text.slice(position, start));
    nodes.push(
      <mark
        key={`${span.placeholder}-restored-${index}`}
        className={`marked ${entityClass(span.label)} ${active === span.placeholder ? "is-linked" : ""}`}
        title={`${span.label} · restored locally`}
        onMouseEnter={() => onHover(span.placeholder)}
        onMouseLeave={() => onHover(null)}
      >
        {text.slice(start, end)}
        <span className="mark-label">{span.label}</span>
      </mark>,
    );
    position = end;
  });
  if (position < text.length) nodes.push(text.slice(position));
  return nodes;
}

function normalize(value: string) {
  return value.toLocaleLowerCase().replace(/[\W_]/g, "");
}

function makeMockResult(text: string, task: "summarize" | "extract", purpose: string, docType?: string): ProcessResult {
  const patterns: Array<{ label: string; regex: RegExp }> = [
    { label: "AADHAAR", regex: /\b(?:\d{4}[- ]?){2}\d{4}\b/g },
    { label: "PAN", regex: /\b[A-Z]{5}\d{4}[A-Z]\b/gi },
    { label: "GSTIN", regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b/gi },
    { label: "VOTER_ID", regex: /\b[A-Z]{3}\d{7}\b/gi },
    { label: "PASSPORT", regex: /\b[A-Z]\d{7}\b/gi },
    { label: "PHONE", regex: /(?:\+91[\s-]?)?\b[6-9]\d{9}\b/g },
    { label: "EMAIL", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
    { label: "ADDRESS", regex: /(?:Address|address)\s*:\s*[^.\n]+(?:\d{6})?/g },
    { label: "PERSON", regex: /(?:Applicant Name|Customer name|Policy holder|name is|naam|hesaru)[ \t]*:[ \t]*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})|(?:naam|hesaru)[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})/gi },
  ];
  const matches: Array<{ label: string; start: number; end: number; value: string }> = [];
  patterns.forEach(({ label, regex }) => {
    for (const match of text.matchAll(regex)) {
      const value = label === "PERSON" ? (match[1] ?? match[2] ?? match[0]) : match[0];
      const offset = match.index ?? 0;
      const start = label === "PERSON" ? offset + match[0].lastIndexOf(value) : offset;
      matches.push({ label, start, end: start + value.length, value });
    }
  });
  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  const entities: MockEntity[] = [];
  const placeholders = new Map<string, string>();
  const nextId: Record<string, number> = {};
  const accepted: typeof matches = [];
  matches.forEach((match) => {
    if (accepted.some((other) => match.start < other.end && match.end > other.start)) return;
    accepted.push(match);
    const key = `${match.label}:${match.value.toLocaleLowerCase()}`;
    if (!placeholders.has(key)) {
      nextId[match.label] = (nextId[match.label] ?? 0) + 1;
      placeholders.set(key, `<${match.label}_${nextId[match.label]}>`);
    }
    entities.push({
      ...match,
      placeholder: placeholders.get(key)!,
      action: (fallbackPolicies[purpose]?.actions[match.label] ?? "mask"),
      score: 0.99,
      source: "demo-pattern",
      pass: 1,
    });
  });
  const blocked = [...new Set(entities.filter((entity) => entity.action === "block").map((entity) => entity.label))];
  if (blocked.length) {
    throw {
      status: 403,
      detail: { error: "blocked_by_policy", labels: blocked, request_id: `demo-${Date.now().toString(36)}` },
    } satisfies GatewayError;
  }
  let sanitized = text;
  [...entities].sort((a, b) => b.start - a.start).forEach((entity) => {
    const token = entity.action === "redact" ? `[REDACTED_${entity.label}]` : entity.placeholder;
    sanitized = `${sanitized.slice(0, entity.start)}${token}${sanitized.slice(entity.end)}`;
    entity.placeholder = token;
  });
  const outboundPayload = JSON.stringify({ model: "demo-local", task, document: sanitized }, null, 2);
  const llmRawResponse = task === "extract"
    ? JSON.stringify({ document_type: docType ?? "document", summary: sanitized.slice(0, 240) }, null, 2)
    : `Summary: ${sanitized.slice(0, 360)}${sanitized.length > 360 ? "…" : ""}`;
  let finalResponse = llmRawResponse;
  const restoreMap = new Map(entities.filter((entity) => entity.action !== "redact").map((entity) => [entity.placeholder, entity.value] as const));
  restoreMap.forEach((value, placeholder) => {
    finalResponse = finalResponse.split(placeholder).join(value);
  });
  return {
    request_id: `demo-${Date.now().toString(36)}`,
    purpose,
    original_text: text,
    sanitized_text: sanitized,
    outbound_payload: outboundPayload,
    entities,
    llm_raw_response: llmRawResponse,
    final_response: finalResponse,
    provider: "demo-local",
    model: "offline mock",
    fallback_used: false,
    attempts: [{ provider: "demo-local", model: "offline mock", external: false, status: "ok", ms: 1 }],
    leak_check: { values_checked: new Set(entities.map((entity) => entity.value)).size, leaks: 0, outbound_sha256: "offline-demo-hash" },
    reinsertion: { restored: [...new Set(entities.filter((entity) => entity.action !== "redact").map((entity) => entity.placeholder))], unresolved: [], dropped: [] },
    timings: { gateway_overhead_ms: 4, detect_ms: 1, mask_ms: 1, llm_ms: 1, reinsert_ms: 1 },
  };
}

function App() {
  const [text, setText] = useState(samples[0].text);
  const [sampleId, setSampleId] = useState(samples[0].id);
  const [task, setTask] = useState<"summarize" | "extract">("summarize");
  const [purpose, setPurpose] = useState("default");
  const [instructions, setInstructions] = useState("");
  const [provider, setProvider] = useState("");
  const [providerOptions, setProviderOptions] = useState<ProviderOption[]>([]);
  const [policies, setPolicies] = useState<Record<string, Policy>>(fallbackPolicies);
  const [health, setHealth] = useState<{ detection_engine: string; backends: string[]; max_upload_bytes?: number } | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(metricsFallback);
  const [result, setResult] = useState<ProcessResult | null>(null);
  const [failure, setFailure] = useState<GatewayFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [toast, setToast] = useState("");
  const [tab, setTab] = useState<"audit" | "metrics" | "policies">("audit");
  const [audit, setAudit] = useState<{ chain_valid: boolean; records: AuditRecord[] } | null>(null);
  const [auditLoading, setAuditLoading] = useState(true);
  const [selectedAudit, setSelectedAudit] = useState<Record<string, string> | null>(null);
  const [requestOpen, setRequestOpen] = useState(false);
  const [attemptsOpen, setAttemptsOpen] = useState(false);
  const [activePlaceholder, setActivePlaceholder] = useState<string | null>(null);
  const [previewMode, setPreviewMode] = useState<"compare" | "original" | "sanitized">("compare");
  const [reviewApproved, setReviewApproved] = useState(false);
  const [uploadedDocument, setUploadedDocument] = useState<UploadedDocument | null>(null);
  const [documentAnalysis, setDocumentAnalysis] = useState<DocumentAnalysis | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [draggingFile, setDraggingFile] = useState(false);
  const toastTimer = useRef<number | null>(null);
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const uploadRef = useRef<HTMLInputElement>(null);
  const imageUploadRef = useRef<HTMLInputElement>(null);

  const activePolicy = policies[purpose] ?? fallbackPolicies[purpose] ?? policies.default;
  const reviewEntities = useMemo(
    () => documentAnalysis?.entities.filter((entity) => entity.pass === 1) ?? [],
    [documentAnalysis],
  );
  const reviewSpans = useMemo(
    () => reviewEntities
      .filter((entity) => entity.start >= 0 && entity.end <= text.length)
      .map((entity) => ({
        start: entity.start,
        end: entity.end,
        label: entity.label,
        placeholder: entity.placeholder,
        value: entity.value,
      }))
      .sort((a, b) => a.start - b.start || b.end - a.end),
    [reviewEntities, text.length],
  );
  const spans = useMemo(() => result ? getSpans(text, result.entities) : [], [result, text]);
  const signalEntities = result ? spans : reviewSpans;
  const signalAvailable = Boolean(result || documentAnalysis);
  const privacySignal = signalAvailable ? Math.min(signalEntities.length * 10, 100) : null;
  const originalValues = useMemo(() => [...new Set(spans.map((span) => span.value))], [spans]);
  const outboundLeaks = useMemo(() => result
    ? originalValues.filter((value) => normalize(value).length >= 4 && normalize(result.outbound_payload).includes(normalize(value)))
    : [], [originalValues, result]);
  const dashboardStats = useMemo(() => {
    const records = audit?.records ?? [];
    const successful = records.filter((record) => record.status === "OK" || record.status === "OK_FALLBACK");
    const documents = successful.filter((record) => record.doc_type?.startsWith("upload:"));
    const entities = records.reduce((sum, record) => sum + Object.values(
      parseJson<Record<string, number>>(record.entity_types, {}),
    ).reduce((count, value) => count + value, 0), 0);
    return { documents: documents.length, entities, requests: records.length };
  }, [audit]);

  const notify = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(""), 3200);
  }, []);

  const refreshAudit = useCallback(async () => {
    const data = await api.audit(50);
    setAudit(data);
  }, []);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
    api.providers().then((data) => {
      setProviderOptions(data.providers);
      setProvider(data.default);
    }).catch(() => undefined);
    api.policies().then(setPolicies).catch(() => undefined);
    api.metrics().then(setMetrics).catch(() => undefined);
    refreshAudit().catch(() => setAudit(null)).finally(() => setAuditLoading(false));
    return () => {
      if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    };
  }, [refreshAudit]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        void runGateway();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  });

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      notify(`${label} copied`);
    } catch {
      notify(`Could not copy ${label.toLocaleLowerCase()}`);
    }
  }

  async function uploadFile(file?: File) {
    if (!file || uploading || busy) return;
    const extension = file.name.split(".").pop()?.toLowerCase();
    const maxBytes = health?.max_upload_bytes ?? 10 * 1024 * 1024;
    if (!["pdf", "docx", "txt", "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"].includes(extension ?? "")) {
      notify("Unsupported file. Choose a PDF, DOCX, TXT, or supported image.");
      return;
    }
    if (file.size > maxBytes) {
      notify(`File exceeds the ${formatBytes(maxBytes)} upload limit.`);
      return;
    }
    setUploading(true);
    setUploadProgress(0);
    setResult(null);
    setFailure(null);
    setDocumentAnalysis(null);
    setUploadedDocument(null);
    setReviewApproved(false);
    try {
      const uploaded = await api.uploadDocument(file, setUploadProgress);
      setUploadedDocument(uploaded);
      setText(uploaded.extracted_text);
      setSampleId("custom");
      setUploadProgress(100);
      const analysis = await api.analyzeDocument(uploaded.document_id, uploaded.access_token, purpose);
      setDocumentAnalysis(analysis);
      notify("Document extracted and sanitized for review.");
    } catch (error) {
      setUploadedDocument(null);
      if (isGatewayError(error)) {
        const detail = typeof error.detail === "string" ? error.detail : errorDetail(error).detail;
        notify(typeof detail === "string" ? detail : `Document upload failed (${error.status}).`);
      } else {
        notify(error instanceof Error ? error.message : "Could not upload this document.");
      }
    } finally {
      setUploading(false);
      if (uploadRef.current) uploadRef.current.value = "";
      if (imageUploadRef.current) imageUploadRef.current.value = "";
    }
  }

  function handleImagePaste(event: ReactClipboardEvent<HTMLTextAreaElement>) {
    const imageItem = Array.from(event.clipboardData.items)
      .find((item) => item.kind === "file" && item.type.startsWith("image/"));
    if (!imageItem) return;

    event.preventDefault();
    if (uploading || busy) {
      notify("Wait for the current request to finish before pasting an image.");
      return;
    }

    const image = imageItem.getAsFile();
    const extension = ({
      "image/png": "png",
      "image/jpeg": "jpg",
      "image/jpg": "jpg",
      "image/tiff": "tiff",
      "image/bmp": "bmp",
      "image/webp": "webp",
    } as Record<string, string>)[imageItem.type.toLowerCase()];
    if (!image || !extension) {
      notify("This clipboard image format is not supported. Paste PNG, JPEG, TIFF, BMP, or WebP.");
      return;
    }

    void uploadFile(new File([image], `pasted-image-${Date.now()}.${extension}`, { type: image.type }));
  }

  function clearUploadedDocument() {
    setUploadedDocument(null);
    setDocumentAnalysis(null);
    setText("");
    setSampleId("custom");
    setResult(null);
    setFailure(null);
    setReviewApproved(false);
  }

  async function changePurpose(nextPurpose: string) {
    setPurpose(nextPurpose);
    setResult(null);
    setReviewApproved(false);
    if (!uploadedDocument) {
      setDocumentAnalysis(null);
      return;
    }
    try {
      setDocumentAnalysis(await api.analyzeDocument(
        uploadedDocument.document_id, uploadedDocument.access_token, nextPurpose,
      ));
    } catch (error) {
      setDocumentAnalysis(null);
      notify(isGatewayError(error) ? `Analysis failed (${error.status}).` : "Could not re-analyze the document.");
    }
  }

  function downloadText(value: string, filename: string) {
    const url = URL.createObjectURL(new Blob([value], { type: "text/plain;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function runGateway() {
    if (!text.trim() || busy || (uploadedDocument && (!documentAnalysis || !reviewApproved))) return;
    setBusy(true);
    setFailure(null);
    setResult(null);
    try {
      const selectedSample = samples.find((sample) => sample.id === sampleId);
      const body = {
        text, task, purpose, instructions: instructions || undefined, provider: provider || undefined,
        ...(selectedSample && sampleId !== "custom" ? { doc_type: selectedSample.docType } : {}),
      };
      const next = uploadedDocument
        ? await api.processDocument({
          document_id: uploadedDocument.document_id, task, purpose,
          instructions: instructions || undefined, provider: provider || undefined,
        }, uploadedDocument.access_token)
        : demoMode
          ? makeMockResult(text, task, purpose, body.doc_type)
          : await api.process(body);
      setResult(next);
      await refreshAudit().catch(() => undefined);
    } catch (error) {
      if (isGatewayError(error)) {
        const detail = errorDetail(error);
        const labels = Array.isArray(detail.labels) ? detail.labels.map(String) : [];
        if (error.status === 403 && detail.error === "blocked_by_policy") {
          setFailure({ kind: "blocked", message: `Blocked by purpose policy: ${labels.join(", ") || "sensitive data"} may not be processed. Nothing left the organisation.`, labels, requestId: String(detail.request_id ?? "") });
        } else if (error.status === 500 && detail.error === "leak_prevented") {
          setFailure({ kind: "leak", message: "Final leak gate stopped the request. Nothing was sent.", requestId: String(detail.request_id ?? "") });
        } else if (error.status === 502) {
          setFailure({ kind: "unavailable", message: "The configured language models are unavailable. Your original text stayed in the gateway.", requestId: String(detail.request_id ?? "") });
        } else {
          notify(`Gateway request failed (${error.status})`);
        }
      } else {
        notify("Network error: could not reach the gateway. Check the API URL or turn on Demo mode.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function openAuditRow(requestId: string) {
    try {
      setSelectedAudit(await api.auditDetail(requestId));
    } catch {
      notify("Could not load the full audit record");
    }
  }

  function chooseSample(id: string) {
    setSampleId(id);
    const selected = samples.find((sample) => sample.id === id);
    if (selected) setText(selected.text);
    setResult(null);
    setFailure(null);
    setUploadedDocument(null);
    setDocumentAnalysis(null);
    setReviewApproved(false);
  }

  const healthBackends = health?.backends?.join(", ") || "backend offline";
  const reportTypes = metrics?.per_type_overlap
    ? Object.entries(metrics.per_type_overlap).map(([name, scores]) => ({
      name, precision: scores.precision * 100, recall: scores.recall * 100,
    }))
    : [];
  const leakIsPresent = result && (result.leak_check.leaks > 0 || outboundLeaks.length > 0);
  const pipelineMessage = busy
    ? "Gateway request in progress"
    : failure
      ? "Stopped safely · nothing else was forwarded"
      : result
        ? "Request completed · response restored locally"
        : documentAnalysis
          ? reviewApproved ? "Preview approved · ready for secure processing" : "Sanitized preview ready · approval required"
          : "Ready · original data stays within the gateway";
  const protectionReady = Boolean(health || demoMode);

  return (
    <MotionConfig reducedMotion="user">
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="DPDP Privacy Gateway home">
          <span className="brand-icon"><Shield size={21} strokeWidth={2.2} /></span>
          <span className="brand-text">DPDP <strong>Privacy Gateway</strong></span>
        </a>
        <nav className="topbar-nav" aria-label="Workspace sections">
          <a href="#overview">Overview</a>
          <a href="#document-intake">Documents</a>
          <a href="#processing">Processing</a>
          <a href="#governance">Governance</a>
        </nav>
        <div className="topbar-status">
          <span className={`status-badge ${health ? "online" : "offline"}`}><span className="status-dot" />{health ? "Gateway connected" : "Gateway offline"}</span>
          <span className="engine-badge"><Fingerprint size={14} />{health?.detection_engine ?? "engine unavailable"}</span>
          <span className="backend-badge"><Network size={14} />{healthBackends}</span>
        </div>
      </header>

      <main className="page-content">
        <motion.section className="hero-panel" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, ease: "easeOut" }}>
          <div className="hero-grid" aria-hidden="true" />
          <div className="hero-copy">
            <div className="hero-kicker"><span className="hero-kicker-dot" /> PRIVACY CONTROL PLANE <span className="hero-kicker-pill">4-STAGE PROTECTION</span></div>
            <h1>Keep sensitive data <span>where it belongs.</span></h1>
            <p>A private processing layer between your documents and AI. Personal values are masked before forwarding, then restored on your network.</p>
            <div className="hero-points">
              <span><LockKeyholeOpen size={14} /> Original data stays local</span>
              <span><ShieldCheck size={14} /> Only sanitized text is forwarded</span>
            </div>
          </div>
          <div className={`hero-side ${protectionReady ? "protection-ready" : "protection-offline"}`}>
            <div className="hero-orbit" aria-hidden="true">
              <span className="orbit-ring orbit-ring-outer" />
              <span className="orbit-ring orbit-ring-inner" />
              <span className="orbit-node orbit-node-one" />
              <span className="orbit-node orbit-node-two" />
              <span className="orbit-node orbit-node-three" />
              <span className="hero-shield"><ShieldCheck size={34} strokeWidth={1.7} /></span>
            </div>
            <div className="hero-float-card hero-float-top"><span className="float-icon"><LockKeyholeOpen size={14} /></span><span><b>Private by design</b><small>Values restored locally</small></span></div>
            <div className="hero-float-card hero-float-bottom"><span className={`float-pulse ${protectionReady ? "" : "pulse-inactive"}`} /><span><b>{health ? "Gateway protection ready" : demoMode ? "Local demo preview" : "Protection inactive"}</b><small>{health ? "Gateway connected" : demoMode ? "No external request" : "Connect gateway to protect"}</small></span></div>
            <label className={`demo-switch ${demoMode ? "demo-active" : ""}`}>
              <span className="switch-copy"><Sparkles size={16} /><span><b>Demo mode</b><small>Offline mock for sample/text input</small></span></span>
              <input type="checkbox" checked={demoMode} onChange={(event) => setDemoMode(event.target.checked)} aria-label="Enable Demo mode" />
              <span className="switch-track"><span /></span>
            </label>
          </div>
        </motion.section>

        <section id="overview" className="dashboard-stats" aria-label="Recent gateway activity">
          <div><span>DOCUMENTS PROCESSED</span><strong>{dashboardStats.documents}</strong><small>within recent audit history</small></div>
          <div><span>PII ENTITIES DETECTED</span><strong>{dashboardStats.entities}</strong><small>across recent requests</small></div>
          <div><span>AI REQUESTS</span><strong>{dashboardStats.requests}</strong><small>recorded in the audit log</small></div>
          <div><span>RECENT ACTIVITY</span><strong>{audit?.records[0]?.status ?? "—"}</strong><small>{audit?.records[0]?.created_at ? new Date(audit.records[0].created_at).toLocaleString() : "No requests yet"}</small></div>
        </section>

        <section id="document-intake" className="document-upload-panel">
          <div className="upload-heading">
            <div><span className="control-kicker">PRIVATE DOCUMENT INTAKE</span><h2>Upload a document</h2></div>
            <span className="input-assurance"><LockKeyholeOpen size={13} /> Stored in gateway memory for up to 15 minutes</span>
          </div>
          <div
            className={`drop-zone ${draggingFile ? "drop-zone-active" : ""} ${uploading ? "drop-zone-busy" : ""}`}
            onDragOver={(event) => { event.preventDefault(); setDraggingFile(true); }}
            onDragLeave={() => setDraggingFile(false)}
            onDrop={(event) => { event.preventDefault(); setDraggingFile(false); void uploadFile(event.dataTransfer.files[0]); }}
          >
            <input ref={uploadRef} type="file" accept=".pdf,.docx,.txt,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain" onChange={(event) => void uploadFile(event.target.files?.[0])} hidden />
            <input ref={imageUploadRef} type="file" accept=".png,.jpg,.jpeg,.tif,.tiff,.bmp,.webp,image/*" onChange={(event) => void uploadFile(event.target.files?.[0])} hidden />
            <span className="upload-icon"><CloudUpload size={23} /></span>
            <div className="drop-copy"><strong>{uploading ? "Uploading and extracting…" : "Upload a document or image"}</strong><span>Drop a PDF, DOCX, TXT, or image · OCR runs locally · maximum {formatBytes(health?.max_upload_bytes ?? 10 * 1024 * 1024)}</span></div>
            <div className="upload-actions">
              <button className="outline-button" type="button" onClick={() => uploadRef.current?.click()} disabled={uploading}>Browse documents</button>
              <button className="outline-button image-upload-button" type="button" onClick={() => imageUploadRef.current?.click()} disabled={uploading}><ImageIcon size={15} /> Browse images</button>
            </div>
          </div>
          {uploading && <div className="upload-progress" role="progressbar" aria-valuenow={uploadProgress} aria-valuemin={0} aria-valuemax={100}>
            <span style={{ width: `${uploadProgress}%` }} /><b>{uploadProgress}%</b>
          </div>}
          {uploadedDocument && <div className="uploaded-file">
            <FileCheck2 size={17} />
            <span><strong>{uploadedDocument.file_name}</strong><small>{formatBytes(uploadedDocument.size_bytes)} · expires in {Math.ceil(uploadedDocument.expires_in_seconds / 60)} min</small></span>
            <button className="icon-button" onClick={clearUploadedDocument} aria-label="Clear uploaded document"><X size={15} /></button>
          </div>}
          <div className="upload-support">Supported: PDF · DOCX · TXT · PNG · JPEG · TIFF · BMP · WebP <span>Scanned PDFs and images are OCR-processed locally; files are not written to disk or included in audit logs.</span></div>
          <div className="language-support">Multilingual name + phone rules: English · Hindi · Kannada · Hinglish · Kannada-English</div>
        </section>

        {documentAnalysis && !result && <section className="document-review">
          <div className="review-heading"><div><span className="control-kicker">PRIVACY ANALYSIS</span><h2>Review extracted and sanitized text</h2></div>
            <div className="review-actions"><span className="entity-count">{reviewEntities.length} entities · {documentAnalysis.detection_engine}</span>
              <div className="preview-switch" role="group" aria-label="Preview layout">
                {(["compare", "original", "sanitized"] as const).map((mode) =>
                  <button type="button" className={previewMode === mode ? "selected" : ""} onClick={() => setPreviewMode(mode)} key={mode}>
                    {mode === "compare" ? "Compare" : mode === "original" ? "Original" : "Sanitized"}
                  </button>)}
              </div>
              <button className="outline-button" onClick={() => downloadText(documentAnalysis.sanitized_text, "sanitized-document.txt")}><Download size={13} /> Download sanitized</button>
            </div>
          </div>
          <div className={`review-grid preview-${previewMode}`}>
            {previewMode !== "sanitized" && <motion.div key="original-preview" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: .22 }}><h3>Extracted original <small>authorized preview · hover values to link</small></h3><pre>{renderMarkedText(text, reviewSpans, activePlaceholder, setActivePlaceholder)}</pre></motion.div>}
            {previewMode !== "original" && <motion.div key="sanitized-preview" initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: .22 }}><h3>Sanitized preview <small>only this content is sent to AI · hover placeholders to link</small></h3><pre>{renderPlaceholders(documentAnalysis.sanitized_text, reviewSpans, activePlaceholder, setActivePlaceholder)}</pre></motion.div>}
          </div>
          <label className={`review-approval ${reviewApproved ? "approved" : ""}`}>
            <input type="checkbox" checked={reviewApproved} onChange={(event) => setReviewApproved(event.target.checked)} />
            <span><strong>I reviewed the sanitized preview and approve this request.</strong><small>Only the sanitized text will be sent to the selected AI provider. Original values remain in the gateway.</small></span>
            <CheckCircle2 size={19} aria-hidden="true" />
          </label>
          <div className="entity-table-wrap review-entities"><table className="entity-table">
            <thead><tr><th>CATEGORY</th><th>ORIGINAL VALUE</th><th>PLACEHOLDER</th><th>CONFIDENCE</th><th>POSITION</th></tr></thead>
            <tbody>{reviewEntities.map((entity, index) => <tr key={`${entity.placeholder}-${entity.start}-${index}`}>
              <td><span className="entity-type">{entity.label}</span></td><td>{entity.value}</td>
              <td><span className={`mini-token ${entityClass(entity.label)}`}>{entity.placeholder}</span></td>
              <td>{Math.round(entity.score * 100)}%</td>
              <td>{entity.start}–{entity.end} ({entity.pass === 1 ? "original" : "sanitized"})</td>
            </tr>)}</tbody>
          </table></div>
          <p className="review-disclaimer">Detection is best-effort and does not guarantee complete anonymization. Review the sanitized text before processing.</p>
        </section>}

        <section id="processing" className="control-panel">
          <div className="control-heading">
            <div><span className="control-kicker">NEW SECURE REQUEST</span><h2>Choose what to process</h2></div>
            <span className="input-assurance"><LockKeyholeOpen size={13} /> Your original input never leaves the gateway</span>
          </div>
          <div className="control-grid">
            <label className="field-group sample-field">
              <span className="field-label">SAMPLE DOCUMENT</span>
              <span className="select-wrap"><FileText size={16} /><select value={sampleId} onChange={(event) => chooseSample(event.target.value)}>
                {samples.map((sample) => <option key={sample.id} value={sample.id}>{sample.name}</option>)}
                <option value="custom">Write your own</option>
              </select><ChevronDown size={15} /></span>
            </label>
            <label className="field-group purpose-field">
              <span className="field-label">PROCESSING PURPOSE</span>
              <span className="select-wrap"><select value={purpose} onChange={(event) => void changePurpose(event.target.value)}>
                {Object.keys(policies).map((name) => <option key={name} value={name}>{name.replaceAll("_", " ")}</option>)}
              </select><ChevronDown size={15} /></span>
              <span className="purpose-description">{activePolicy?.description ?? "Select a purpose policy for this request."}</span>
            </label>
            <div className="field-group task-field">
              <span className="field-label">LLM TASK</span>
              <div className="segmented-control" role="group" aria-label="LLM task">
                <button className={task === "summarize" ? "selected" : ""} onClick={() => setTask("summarize")}>Summarize</button>
                <button className={task === "extract" ? "selected" : ""} onClick={() => setTask("extract")}>Extract</button>
              </div>
            </div>
            <label className="field-group provider-field">
              <span className="field-label">AI PROVIDER / MODEL</span>
              <span className="select-wrap"><select value={provider} onChange={(event) => setProvider(event.target.value)} aria-label="AI provider and model">
                {providerOptions.map((option) => <option key={option.id} value={option.id}>{option.id} · {option.model}{option.available ? "" : " (key not set; fallback used)"}</option>)}
                {!providerOptions.length && <option value="mock">mock · mock-llm-1</option>}
              </select><ChevronDown size={15} /></span>
            </label>
            <div className="run-cell">
              <button className="primary-button" onClick={() => void runGateway()} disabled={busy || uploading || !text.trim() || Boolean(uploadedDocument && (!documentAnalysis || !reviewApproved))}>
                {busy ? <><RotateCw className="spin" size={16} /> Processing…</> : <><ShieldCheck size={17} /> Run securely <span className="button-shortcut">⌘ ↵</span></>}
              </button>
              {uploadedDocument && !documentAnalysis && <small className="run-hint">Document analysis is required before processing.</small>}
              {documentAnalysis && !reviewApproved && <small className="run-hint">Review and approve the sanitized preview to continue.</small>}
            </div>
            <label className="instruction-field">
              <span className="field-label">QUESTION OR INSTRUCTION</span>
              <textarea value={instructions} onChange={(event) => setInstructions(event.target.value)} rows={2} placeholder={task === "extract" ? "Ask a specific question; Extract returns up to 3 relevant lines." : "Ask a question about the document or leave blank for the selected task."} />
            </label>
          </div>
          <div className={`pipeline-status ${busy ? "pipeline-running" : ""} ${result ? "pipeline-complete" : ""} ${failure ? "pipeline-stopped" : ""}`} role="status" aria-live="polite">
            <div className="pipeline-heading"><span><Activity size={13} /> SECURE PROCESSING FLOW</span><b>{pipelineMessage}</b></div>
            <div className={`security-flow ${busy ? "flow-busy" : ""} ${result ? "flow-complete" : ""} ${failure ? "flow-stopped" : ""}`} aria-label={`Document processing flow. ${pipelineMessage}`}>
              <span className="flow-track" aria-hidden="true" />
              {busy && <motion.span className="flow-packet" aria-hidden="true" animate={{ left: ["0%", "100%"] }} transition={{ duration: 2, repeat: Infinity, ease: "linear" }} />}
              <div className="flow-steps">
                {flowSteps.map(({ label, icon: Icon }, index) => {
                  const done = Boolean(result) || (Boolean(documentAnalysis) && index < 3) || (Boolean(text.trim()) && index === 0);
                  return <div className={`flow-step ${done ? "done" : ""}`} key={label} aria-label={`${label}: ${done ? "complete" : "pending"}`}>
                    <span className="flow-node">{done ? <Check size={15} /> : <Icon size={15} />}</span>
                    <span className="flow-label">{label}</span>
                  </div>;
                })}
              </div>
            </div>
          </div>
          <div className="workflow-insights">
            <motion.aside className="privacy-signal" initial={{ opacity: 0, scale: .97 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: .3 }}>
              <div className="signal-copy"><span className="field-label">LIVE PRIVACY RISK SIGNAL</span><small>Heuristic from the current detection result</small></div>
              <div className={`signal-gauge ${privacySignal === null ? "signal-pending" : privacySignal > 0 ? "signal-detected" : "signal-clear"}`} role="img" aria-label={privacySignal === null ? "Privacy risk signal awaits analysis" : `Privacy risk signal ${privacySignal} out of 100 based on ${signalEntities.length} detected entities`}>
                <svg viewBox="0 0 96 96" aria-hidden="true">
                  <circle className="gauge-track" cx="48" cy="48" r="39" />
                  <motion.circle className="gauge-value" cx="48" cy="48" r="39" initial={{ strokeDashoffset: 245 }} animate={{ strokeDashoffset: privacySignal === null ? 245 : 245 * (1 - privacySignal / 100) }} transition={{ duration: .8, ease: "easeOut" }} />
                </svg>
                <div><motion.strong key={privacySignal ?? "pending"} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }}>{privacySignal ?? "—"}</motion.strong><span>/100</span></div>
              </div>
              <div className="signal-details">              <strong>{privacySignal === null ? "Awaiting analysis" : signalEntities.length ? `${signalEntities.length} ${signalEntities.length === 1 ? "entity" : "entities"} detected` : "No entities detected"}</strong><small>{privacySignal === null ? "Upload a document or process text to calculate." : "10 heuristic points per detected entity · capped at 100."}</small><small>Not a measure of document safety or a guarantee of anonymization.</small></div>
            </motion.aside>
          </div>
        </section>

        <AnimatePresence mode="wait">
        {failure && <motion.section key={`failure-${failure.kind}`} className={`failure-card failure-${failure.kind}`} role="alert" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: .22 }}>
          {failure.kind === "blocked" ? <ShieldAlert size={20} /> : failure.kind === "unavailable" ? <AlertTriangle size={20} /> : <ShieldAlert size={20} />}
          <div className="failure-copy"><strong>{failure.kind === "blocked" ? "Blocked by purpose policy" : failure.kind === "leak" ? "Final leak gate stopped the request" : "Language model unavailable"}</strong>
            <span>{failure.message}</span>{failure.requestId && <small>Request ID: {failure.requestId}</small>}</div>
          {failure.kind === "unavailable" && <button className="outline-button" onClick={() => void runGateway()}><RotateCw size={14} /> Retry</button>}
          <button className="icon-button close-failure" aria-label="Dismiss error" onClick={() => setFailure(null)}><X size={16} /></button>
        </motion.section>}
        </AnimatePresence>

        <section className={`columns-grid ${result ? "has-result" : ""}`}>
          <article className="data-card original-card">
            <div className="card-heading heading-original">
              <div className="card-heading-icon"><LockKeyholeOpen size={17} /></div>
              <div><h2>Original input</h2><p>Stays inside your network</p></div>
              {result && <span className="entity-count">{spans.length} found</span>}
            </div>
            {result ? <div className="text-panel marked-text" aria-label="Original text with detected entities">
              {renderMarkedText(text, spans, activePlaceholder, setActivePlaceholder)}
            </div> : <div className="editor-wrap">
              <textarea ref={editorRef} value={text} onPaste={handleImagePaste} onChange={(event) => { setText(event.target.value); setSampleId("custom"); setUploadedDocument(null); setDocumentAnalysis(null); setReviewApproved(false); setFailure(null); }} placeholder="Paste or type sensitive text here…" aria-label="Original text" />
              <div className="editor-foot"><span><LockKeyholeOpen size={12} /> Local input · never sent directly</span><span className="paste-image-hint" title="Focus this input and press Ctrl+V to upload a copied image"><ImageIcon size={12} /> Ctrl+V to paste image</span><span>{text.length.toLocaleString()} chars</span></div>
            </div>}
          </article>

          <article className="data-card outbound-card">
            <div className="card-heading heading-outbound">
              <div className="card-heading-icon"><ShieldCheck size={17} /></div>
              <div><h2>Outbound sanitized payload</h2><p>What the external LLM sees</p></div>
              {result && <span className="safe-chip"><CheckCircle2 size={12} /> Sanitized</span>}
            </div>
            {result ? <>
              <div className="text-panel marked-text payload-text">
                {renderPlaceholders(result.sanitized_text, spans, activePlaceholder, setActivePlaceholder)}
              </div>
              <div className="entity-table-wrap">
                <table className="entity-table">
                  <thead><tr><th>TYPE</th><th>PLACEHOLDER</th><th>ACTION</th><th>CONFIDENCE</th></tr></thead>
                  <tbody>{result.entities.map((entity, index) => <tr key={`${entity.placeholder}-${index}`}>
                    <td><span className={`type-dot ${entityClass(entity.label)}`} /><span className="entity-type">{entity.label}</span></td>
                    <td><span className={`mini-token ${entityClass(entity.label)}`}>{entity.placeholder}</span></td>
                    <td><span className={`action-label action-${entity.action}`}>{entity.action}</span></td>
                    <td>{Math.round(entity.score * 100)}%</td>
                  </tr>)}</tbody>
                </table>
                {!result.entities.length && <div className="empty-table">No entities were detected in this request.</div>}
              </div>
              <div className="sent-to-row"><span>Sent to</span><b>{result.provider}</b><span>/</span><code>{result.model}</code>{result.fallback_used && <span className="fallback-tag">Fallback used</span>}</div>
            </> : <div className="column-empty outbound-empty">
              <span className="empty-graphic empty-green"><ShieldCheck size={23} /></span>
              <strong>Sanitized output appears here</strong>
              <span>Detected values are replaced before anything is forwarded.</span>
            </div>}
          </article>

          <article className="data-card response-card">
            <div className="card-heading heading-response">
              <div className="card-heading-icon"><ArrowDownToLine size={17} /></div>
              <div><h2>Final response</h2><p>After local reinsertion</p></div>
              {result && <span className="local-chip"><LockKeyholeOpen size={12} /> Local restore</span>}
            </div>
            {result ? <>
              <div className="text-panel response-text marked-text">
                {renderRestored(result.final_response, spans, activePlaceholder, setActivePlaceholder)}
              </div>
              <div className="reinsertion-caption">
                <span><b>{result.reinsertion.restored.length}</b> restored</span><i />
                <span><b>{result.reinsertion.dropped.length}</b> dropped by LLM</span><i />
                <span><b>{result.reinsertion.unresolved.length}</b> unknown placeholders left untouched</span>
              </div>
              <div className="response-actions">
                <button className="outline-button" onClick={() => void copy(result.final_response, "Restored response")}><Clipboard size={13} /> Copy restored</button>
                <button className="outline-button" onClick={() => downloadText(result.final_response, "privacy-gateway-response.txt")}><Download size={13} /> Download</button>
                <button className="outline-button" onClick={() => void copy(result.llm_raw_response, "Sanitized AI response")}><Clipboard size={13} /> Copy sanitized AI response</button>
                <button className="outline-button" onClick={() => downloadText(result.llm_raw_response, "sanitized-ai-response.txt")}><Download size={13} /> Download sanitized</button>
              </div>
              <details className="sanitized-response">
                <summary>View sanitized AI response · placeholders intact</summary>
                <pre>{result.llm_raw_response}</pre>
              </details>
            </> : <div className="column-empty response-empty">
              <span className="empty-graphic empty-blue"><ArrowDownToLine size={22} /></span>
              <strong>Your private response lands here</strong>
              <span>Values are restored locally after the LLM responds.</span>
            </div>}
          </article>
        </section>

        {!result && !failure && <div className="empty-prompt"><CircleHelp size={15} /><span>Choose a sample document or write your own, then run it through the gateway.</span></div>}

        <AnimatePresence>
        {result && <motion.section className={`verification-banner ${leakIsPresent ? "verification-danger" : "verification-safe"}`} aria-live="polite" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: .24 }}>
          <div className="verification-main">
            {leakIsPresent ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
            <div><strong>{leakIsPresent ? "LEAK DETECTED" : "0 raw PII values found in outbound payload"}</strong>
              <span>{leakIsPresent ? `${outboundLeaks.length || result.leak_check.leaks} original value(s) appear in the exact outbound request.` : "The outbound request passed the client-side value check and backend leak gate."}</span></div>
          </div>
          <div className="verification-details">
            <span><b>{result.leak_check.values_checked}</b> values checked</span>
            <span className="hash-value"><b>SHA-256</b> {result.leak_check.outbound_sha256.slice(0, 16)}… <button className="copy-hash" onClick={() => void copy(result.leak_check.outbound_sha256, "Hash")} aria-label="Copy full SHA-256"><Clipboard size={13} /></button></span>
            <span><Clock3 size={13} /> gateway overhead <b>{(result.timings.gateway_overhead_ms ?? 0).toFixed(1)} ms</b></span>
          </div>
        </motion.section>}
        </AnimatePresence>

        {result && <div className="detail-accordions">
          <section className={`accordion ${requestOpen ? "open" : ""}`}>
            <button className="accordion-trigger" onClick={() => setRequestOpen(!requestOpen)} aria-expanded={requestOpen}>
              <span className="accordion-title"><ChevronRight size={16} className="accordion-chevron" /> Exact request body sent to the external model</span>
              <span className="accordion-action" onClick={(event) => { event.stopPropagation(); void copy(result.outbound_payload, "Request body"); }}><Clipboard size={13} /> Copy JSON</span>
            </button>
            {requestOpen && <pre className="json-block">{JSON.stringify(parseJson(result.outbound_payload, result.outbound_payload), null, 2)}</pre>}
          </section>
          <section className={`accordion ${attemptsOpen ? "open" : ""}`}>
            <button className="accordion-trigger" onClick={() => setAttemptsOpen(!attemptsOpen)} aria-expanded={attemptsOpen}>
              <span className="accordion-title"><ChevronRight size={16} className="accordion-chevron" /> Attempts <span className="attempt-count">{result.attempts.length}</span></span>
            </button>
            {attemptsOpen && <div className="attempt-list">{result.attempts.map((attempt, index) =>
              <div className="attempt-row" key={`${attempt.provider}-${index}`}>
                <span className={`attempt-marker ${attempt.status === "ok" ? "attempt-ok" : "attempt-failed"}`}>{attempt.status === "ok" ? <Check size={12} /> : <X size={12} />}</span>
                <div className="attempt-info"><b>{attempt.provider}</b><span>{attempt.model} · {attempt.external ? "external" : "local"} · {attempt.status}</span>{attempt.error && <small>{attempt.error}</small>}</div>
                {typeof attempt.ms === "number" && <span className="attempt-duration">{attempt.ms.toFixed(1)} ms</span>}
              </div>)}</div>}
          </section>
        </div>}

        <section id="governance" className="workspace-tabs">
          <div className="tab-header" role="tablist">
            <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")} role="tab"><Activity size={15} /> Audit log {audit && <span className="tab-count">{audit.records.length}</span>}</button>
            <button className={tab === "metrics" ? "active" : ""} onClick={() => setTab("metrics")} role="tab"><Fingerprint size={15} /> Metrics report</button>
            <button className={tab === "policies" ? "active" : ""} onClick={() => setTab("policies")} role="tab"><Shield size={15} /> Policies <span className="tab-count">{Object.keys(policies).length}</span></button>
          </div>
          <motion.div className="tab-content" key={tab} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .18 }}>
            {tab === "audit" && <AuditTab audit={audit} onOpen={openAuditRow} loading={auditLoading} />}
            {tab === "metrics" && <Suspense fallback={<MetricsSkeleton />}><MetricsTab metrics={metrics} data={reportTypes} /></Suspense>}
            {tab === "policies" && <PoliciesTab policies={policies} />}
          </motion.div>
        </section>

        <footer className="page-footer">
          <span><Shield size={14} /> Detect the sensitive. Mask the personal. Process securely. Restore locally.</span>
          <span>API <code>{getApiUrl()}</code></span>
        </footer>
      </main>

      {selectedAudit && <div className="drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedAudit(null); }}>
        <aside className="audit-drawer" aria-label="Audit record details">
          <div className="drawer-header"><div><span className="eyebrow">AUDIT RECORD</span><h2>{selectedAudit.request_id}</h2></div><button className="icon-button" onClick={() => setSelectedAudit(null)} aria-label="Close audit details"><X size={18} /></button></div>
          <div className="drawer-fields">
            {["created_at", "document_id", "purpose", "status", "provider", "model", "detection_engine", "outbound_sha256", "error"].filter((key) => selectedAudit[key]).map((key) =>
              <div className="drawer-field" key={key}><span>{key.replaceAll("_", " ")}</span><b>{selectedAudit[key]}</b></div>)}
          </div>
          <div className="drawer-section-title">Exact outbound payload</div>
          <pre className="json-block drawer-json">{selectedAudit.outbound_payload}</pre>
          <button className="outline-button drawer-copy" onClick={() => void copy(selectedAudit.outbound_payload ?? "", "Outbound payload")}><Clipboard size={14} /> Copy payload</button>
        </aside>
      </div>}

      <AnimatePresence>{toast && <motion.div className="toast-message" role="status" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 8 }} transition={{ duration: .18 }}><AlertTriangle size={15} />{toast}<button onClick={() => setToast("")} aria-label="Dismiss notification"><X size={14} /></button></motion.div>}</AnimatePresence>
    </div>
    </MotionConfig>
  );
}

function AuditTab({ audit, onOpen, loading }: { audit: { chain_valid: boolean; records: AuditRecord[] } | null; onOpen: (requestId: string) => void; loading: boolean }) {
  if (loading) return <div className="audit-skeleton" aria-label="Loading audit history" aria-busy="true">
    <span className="skeleton-line skeleton-heading" />
    {[0, 1, 2].map((row) => <span className="skeleton-line skeleton-row" key={row} />)}
  </div>;
  return <div className="audit-panel">
    <div className="panel-title-row"><div><h3>Recent requests</h3><p>Immutable records of outbound payloads and model attempts.</p></div>
      <span className={`chain-badge ${audit?.chain_valid ? "chain-valid" : "chain-invalid"}`}>{audit?.chain_valid ? <CheckCircle2 size={14} /> : <ShieldAlert size={14} />}{audit ? (audit.chain_valid ? "Hash chain intact" : "Chain verification failed") : "Audit unavailable"}</span>
    </div>
    <div className="table-scroll"><table className="audit-table"><thead><tr><th>REQUEST ID</th><th>DOCUMENT ID</th><th>TIME</th><th>PURPOSE</th><th>STATUS</th><th>PROVIDER / MODEL</th><th>ENTITIES</th><th>HASH</th></tr></thead>
      <tbody>{audit?.records.map((record) => {
        const counts = parseJson<Record<string, number>>(record.entity_types, {});
        return <tr key={record.request_id} onClick={() => onOpen(record.request_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") onOpen(record.request_id); }}>
          <td><button className="request-id" onClick={(event) => { event.stopPropagation(); onOpen(record.request_id); }}>{record.request_id}<ChevronRight size={12} /></button></td>
          <td><code>{record.document_id?.slice(0, 12) || "—"}</code></td>
          <td>{record.created_at ? new Date(record.created_at).toLocaleString() : "—"}</td>
          <td>{record.purpose?.replaceAll("_", " ") || "—"}</td>
          <td><span className={`status-pill status-${(record.status || "").toLowerCase().replaceAll("_", "-")}`}>{record.status || "UNKNOWN"}</span></td>
          <td><b>{record.provider || "—"}</b><small>{record.model}</small></td>
          <td><span className="entity-badges">{Object.entries(counts).map(([type, count]) => <span className={`entity-badge ${entityClass(type)}`} key={type}>{type} <b>{count}</b></span>)}</span></td>
          <td><code>{record.outbound_sha256?.slice(0, 10) || "—"}</code></td>
        </tr>;
      })}</tbody></table>
    </div>
    {!audit?.records.length && <div className="empty-tab"><Activity size={18} />{audit ? "No audit records yet. Process a document to create the first record." : "Connect the backend or enable Demo mode to view audit data."}</div>}
  </div>;
}

function MetricsSkeleton() {
  return <div className="metrics-skeleton" aria-label="Loading metrics report" aria-busy="true">
    <span className="skeleton-line skeleton-heading" />
    <div>{[0, 1, 2].map((item) => <span className="skeleton-line skeleton-kpi" key={item} />)}</div>
    <span className="skeleton-line skeleton-chart" />
  </div>;
}

function PoliciesTab({ policies }: { policies: Record<string, Policy> }) {
  return <div className="policies-panel">
    <div className="panel-title-row"><div><h3>Purpose-based policies</h3><p>Actions applied to detected data before a request can leave the gateway.</p></div></div>
    <div className="policy-grid">{Object.entries(policies).map(([name, policy]) => {
      const actions = Object.entries(policy.actions ?? {});
      return <article className="policy-card" key={name}>
        <div className="policy-card-heading"><span className="policy-icon"><Shield size={15} /></span><h4>{name.replaceAll("_", " ")}</h4></div>
        <p>{policy.description}</p>
        <div className="policy-actions"><span className="field-label">DEFAULT ACTION</span><span className={`action-label action-${policy.default}`}>{policy.default}</span></div>
        {actions.length > 0 && <div className="policy-entity-list">{actions.map(([label, action]) => <span key={label} className="policy-entity-row"><span className={`type-dot ${entityClass(label)}`} />{label}<b className={`action-label action-${action}`}>{action}</b></span>)}</div>}
      </article>;
    })}</div>
  </div>;
}

export default App;
