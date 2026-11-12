export type Entity = {
  label: string;
  placeholder: string;
  action: string;
  start: number;
  end: number;
  score: number;
  source: string;
  pass: number;
};

export type ProcessResult = {
  request_id: string;
  purpose: string;
  original_text?: string;
  sanitized_text: string;
  outbound_payload: string;
  entities: Entity[];
  llm_raw_response: string;
  final_response: string;
  provider: string;
  model: string;
  fallback_used: boolean;
  attempts: Attempt[];
  leak_check: { values_checked: number; leaks: number; outbound_sha256: string };
  reinsertion: { restored: string[]; unresolved: string[]; dropped: string[] };
  timings: Record<string, number>;
  detection_engine?: string;
};

export type Attempt = {
  provider: string;
  model: string;
  external: boolean;
  status: string;
  payload?: string;
  payload_sha256?: string;
  error?: string;
  ms?: number;
};

export type Policy = {
  description: string;
  actions: Record<string, string>;
  default: string;
};

export type AuditRecord = Record<string, string> & {
  request_id: string;
  created_at: string;
  purpose: string;
  status: string;
  provider: string;
  model: string;
  entity_types: string;
  outbound_sha256: string;
};

export type AuditResponse = {
  chain_valid: boolean;
  records: AuditRecord[];
};

export type Metrics = {
  pii_leakage_count?: number;
  reinsertion?: { accuracy?: number; restored_correctly?: number; total_checked?: number };
  latency_ms?: { gateway_overhead_p95?: number };
  per_type_overlap?: Record<string, { precision: number; recall: number; f1: number }>;
  audit_chain_valid?: boolean;
};

export type GatewayError = {
  status: number;
  detail: unknown;
};
