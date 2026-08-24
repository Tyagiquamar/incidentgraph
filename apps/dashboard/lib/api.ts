// API base URL and shared typed fetch helpers for the dashboard.

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8090";

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`GET ${path}: ${res.status}`);
  }
  return (await res.json()) as T;
}

export async function apiPost<T>(
  path: string,
  body?: unknown
): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`POST ${path}: ${res.status}`);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------- types

export interface Incident {
  id: string;
  title: string;
  description: string;
  service: string;
  severity: string;
  status: string;
  created_at: string;
}

export interface AgentRun {
  id: string;
  incident_id: string;
  agent_backend: string;
  model: string;
  status: string;
  current_phase: string;
  termination_reason: string;
  total_tokens: number;
  total_cost_cents: number;
  latency_ms: number;
  error: string;
}

export interface AgentStep {
  id: string;
  run_id: string;
  step_number: number;
  step_type: string;
  state: string;
  latency_ms: number;
}

export interface ToolCall {
  id: string;
  run_id: string;
  tool_name: string;
  risk_level: string;
  policy_decision: string;
  status: string;
  result_reference: string;
  durable_execution_id: string;
  error: string;
}

export interface Hypothesis {
  id: string;
  statement: string;
  confidence: number;
  status: string;
  rank: number;
  root_cause_category: string;
}

export interface EvidenceNode {
  id: string;
  type: string;
  source: string;
  source_reference: string;
  content: string;
  trust_level: string;
}

export interface EvidenceEdge {
  id: string;
  source_node_id: string;
  target_hypothesis_id: string;
  relationship: string;
  rationale: string;
  confidence: number;
}

export interface RetrievalResult {
  chunk_id: string;
  document_id: string;
  text: string;
  combined_score: number;
  metadata: Record<string, unknown>;
}
