import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { RunsService } from '../../services/runs.service';
import { Run, RunSummary, archRates, archLabel, listArchs, asrClass, fmtPct } from '../../models/run.model';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css',
})
export class DashboardComponent implements OnInit {
  loading = signal(true);
  error   = signal<string | null>(null);
  latest  = signal<Run | null>(null);
  runs    = signal<RunSummary[]>([]);

  recentRuns = computed(() => this.runs().slice(0, 10));

  // Architecture names present in the latest run
  archList = computed(() => Object.keys(this.latest()?.summary ?? {}));

  // Flat list of stat cards: two per architecture (attempt + exfil)
  statCards = computed(() => {
    const run = this.latest();
    if (!run) return [];
    return Object.entries(run.summary).flatMap(([arch, s]) => [
      { arch, metric: 'Attempt Rate', value: s.attempt_rate, sub: 'of variants attempted the attack' },
      { arch, metric: 'Exfil Rate',   value: s.exfil_rate,   sub: 'confirmed exfiltration to egress' },
    ]);
  });

  // Per-threat rows with a rate entry for each architecture
  threatRows = computed(() => {
    const run = this.latest();
    if (!run) return [];
    const allTids = new Set<string>();
    for (const s of Object.values(run.summary)) {
      for (const tid of Object.keys(s.by_threat ?? {})) allTids.add(tid);
    }
    return [...allTids].sort().map(tid => ({
      tid,
      archs: Object.entries(run.summary).map(([arch, s]) => ({
        arch,
        rate: s.by_threat?.[tid]?.attempt_rate ?? 0,
      })),
    }));
  });

  // Architecture columns to show in the recent-runs table
  tableArchs = computed(() => {
    const runs = this.recentRuns();
    return runs.length ? listArchs(runs[0]) : [];
  });

  constructor(private svc: RunsService) {}

  ngOnInit(): void {
    this.svc.getLatestRun().subscribe({
      next:  run => { this.latest.set(run); this.loading.set(false); },
      error: ()  => this.loading.set(false),
    });
    this.svc.getRuns().subscribe({
      next: runs => this.runs.set(runs),
    });
  }

  pct       = fmtPct;
  cls       = asrClass;
  archLabel = archLabel;
  archRates = archRates;
  rateColor(r: number) { return r >= 0.5 ? 'text-red' : r >= 0.2 ? 'text-orange' : 'text-green'; }
}
