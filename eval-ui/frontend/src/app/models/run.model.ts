export interface VariantSummary {
  attempt_rate: number;
  exfil_rate:   number;
  attempt:      number;
  exfil:        number;
  total:        number;
  description:  string;
  rules_fired:  string[];
}

export interface ConverterStats {
  attempt_rate: number;
  exfil_rate:   number;
  attempt:      number;
  exfil:        number;
  total:        number;
}

export interface ArchSummary {
  attempt_rate:   number;
  exfil_rate:     number;
  total_variants: number;
  by_variant:     Record<string, VariantSummary>;
  by_threat:      Record<string, { attempt_rate: number }>;
  by_converter?:  Record<string, ConverterStats>;
}

export interface ArchRates {
  attempt_rate: number;
  exfil_rate:   number;
}

// Run_id / ts / trials are fixed; all other keys are arch names → ArchRates.
export interface RunSummary {
  run_id: string;
  ts:     string;
  trials: number;
  [arch: string]: ArchRates | string | number;
}

export interface TrialResult {
  variant_id:     string;
  threat_id:      string;
  trial:          number;
  agent_response: string;
  score:          string;
  category:       string;
  converter?:     string;    // converter applied to this trial; "none" = plain baseline
  task_sent?:     string;    // actual prompt sent to the agent (post-converter)
  task_original?: string;    // original baseline prompt before any converter was applied
}

// summary keys are arch names; run-level keys are arch names → TrialResult[].
export interface Run {
  run_id:      string;
  trials:      number;
  summary:     Record<string, ArchSummary>;
  converters?: string[];     // converter names used by the experiment, e.g. ["none","base64"]
  [arch: string]: TrialResult[] | string | number | string[] | Record<string, ArchSummary> | undefined;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const _SUMMARY_META = new Set(['run_id', 'ts', 'trials']);

export function listArchs(run: RunSummary): string[] {
  return Object.keys(run).filter(k => !_SUMMARY_META.has(k));
}

export function archRates(run: RunSummary, arch: string): ArchRates {
  return (run[arch] as ArchRates) ?? { attempt_rate: 0, exfil_rate: 0 };
}

export const ARCH_LABEL: Record<string, string> = {
  react:          'ReAct',
  coder_reviewer: 'Coder-Reviewer',
  policy_guard:   'Policy-Guard',
};

export function archLabel(arch: string): string {
  return ARCH_LABEL[arch] ?? arch;
}

export function asrClass(rate: number): string {
  if (rate >= 0.5) return 'badge-high';
  if (rate >= 0.2) return 'badge-mid';
  if (rate >  0)   return 'badge-low';
  return 'badge-zero';
}

export function fmtPct(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}
