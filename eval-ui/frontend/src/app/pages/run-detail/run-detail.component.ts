import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { RunsService } from '../../services/runs.service';
import { Run, TrialResult, VariantSummary, ConverterStats, archLabel, asrClass, fmtPct } from '../../models/run.model';

interface TrialResponse {
  trial:          number;
  converter:      string;
  category:       string;
  task_sent:      string;
  task_original:  string;
  agent_response: string;
}

interface VariantRow {
  variant_id:   string;
  description:  string;
  attempt_rate: number;
  exfil_rate:   number;
  attempt:      number;
  exfil:        number;
  total:        number;
  rules_fired:  string[];
  responses:    TrialResponse[];
}

interface ConverterRow {
  converter:    string;
  attempt_rate: number;
  exfil_rate:   number;
  attempt:      number;
  exfil:        number;
  total:        number;
}

@Component({
  selector: 'app-run-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './run-detail.component.html',
  styleUrl: './run-detail.component.css',
})
export class RunDetailComponent implements OnInit {
  runId!: string;

  loading    = signal(true);
  error      = signal<string | null>(null);
  run        = signal<Run | null>(null);
  activeArch = signal<string>('react');
  modalRow   = signal<VariantRow | null>(null);

  summaryText    = signal('');
  summaryLoading = signal(false);
  summaryCached  = signal(false);
  summaryError   = signal<string | null>(null);

  archList = computed(() => Object.keys(this.run()?.summary ?? {}));

  totalVariants = computed(() => {
    const r = this.run();
    if (!r) return 0;
    const first = Object.values(r.summary)[0];
    return first ? Object.keys(first.by_variant).length : 0;
  });

  // Top-level converter list (set by run_experiment when --converters is used).
  converters = computed<string[]>(() => this.run()?.converters ?? []);

  activeRows = computed<VariantRow[]>(() => {
    const r = this.run();
    if (!r) return [];
    const arch      = this.activeArch();
    const archData  = r.summary[arch];
    if (!archData) return [];
    const byVariant = archData.by_variant;
    const trials    = (r[arch] as TrialResult[]) ?? [];

    return Object.entries(byVariant)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([vid, vs]: [string, VariantSummary]) => ({
        variant_id:   vid,
        description:  vs.description,
        attempt_rate: vs.attempt_rate,
        exfil_rate:   vs.exfil_rate,
        attempt:      vs.attempt,
        exfil:        vs.exfil,
        total:        vs.total,
        rules_fired:  vs.rules_fired ?? [],
        responses:    trials
          .filter(t => t.variant_id === vid && t.agent_response)
          .sort((a, b) =>
            (a.converter ?? '').localeCompare(b.converter ?? '') ||
            (a.trial ?? 0) - (b.trial ?? 0)
          )
          .map(t => ({
            trial:          t.trial,
            converter:      t.converter ?? 'none',
            category:       t.category,
            task_sent:      t.task_sent ?? '',
            task_original:  t.task_original ?? '',
            agent_response: t.agent_response,
          })),
      }));
  });

  // Per-converter breakdown for the active arch. "none" (the plain baseline)
  // is sorted to the front; other converters follow alphabetically.
  activeConvRows = computed<ConverterRow[]>(() => {
    const r = this.run();
    if (!r) return [];
    const archData = r.summary[this.activeArch()];
    const byConv = archData?.by_converter;
    if (!byConv) return [];

    const entries = Object.entries(byConv) as [string, ConverterStats][];
    return entries
      .sort(([a], [b]) => (a === 'none' ? -1 : b === 'none' ? 1 : a.localeCompare(b)))
      .map(([name, cs]) => ({
        converter:    name,
        attempt_rate: cs.attempt_rate,
        exfil_rate:   cs.exfil_rate,
        attempt:      cs.attempt,
        exfil:        cs.exfil,
        total:        cs.total,
      }));
  });

  constructor(private route: ActivatedRoute, private svc: RunsService) {}

  ngOnInit(): void {
    this.runId = this.route.snapshot.paramMap.get('id')!;
    this.svc.getRun(this.runId).subscribe({
      next: run => {
        this.run.set(run);
        this.loading.set(false);
        // Default to the first available architecture
        const archs = Object.keys(run.summary);
        if (archs.length) this.activeArch.set(archs[0]);
      },
      error: err => { this.error.set(err.message ?? 'Failed to load run'); this.loading.set(false); },
    });
    this.svc.getSummary(this.runId).subscribe({
      next: ({ summary, cached }) => {
        if (summary) {
          this.summaryText.set(summary);
          this.summaryCached.set(cached);
        }
      },
    });
  }

  generateSummary(): void {
    this.summaryText.set('');
    this.summaryError.set(null);
    this.summaryCached.set(false);
    this.summaryLoading.set(true);

    this.svc.generateSummary(this.runId).subscribe({
      next: event => {
        if (event.text)  this.summaryText.update(t => t + event.text!);
        if (event.error) this.summaryError.set(event.error);
        if (event.done)  this.summaryLoading.set(false);
      },
      error:    err => { this.summaryError.set(err.message ?? 'Generation failed'); this.summaryLoading.set(false); },
      complete: ()  => this.summaryLoading.set(false),
    });
  }

  openModal(row: VariantRow): void { this.modalRow.set(row); }
  closeModal(): void               { this.modalRow.set(null); }

  // Color the category chip in the response modal by attack severity.
  // RAW_EXPOSURE counts as low (guardrail caught it but markers were in raw output).
  categoryClass(cat: string): string {
    if (cat === 'EXFILTRATION') return 'badge-high';
    if (cat === 'SOFT_LEAK')    return 'badge-mid';
    if (cat === 'PARTIAL_EXEC' || cat === 'CONFUSED_DEPUTY' || cat === 'RAW_EXPOSURE') return 'badge-low';
    return 'badge-zero';
  }

  pct       = fmtPct;
  cls       = asrClass;
  archLabel = archLabel;
}
