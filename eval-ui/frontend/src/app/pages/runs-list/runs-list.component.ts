import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { RunsService } from '../../services/runs.service';
import { RunSummary, archRates, archLabel, listArchs, asrClass, fmtPct } from '../../models/run.model';

@Component({
  selector: 'app-runs-list',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './runs-list.component.html',
  styleUrl: './runs-list.component.css',
})
export class RunsListComponent implements OnInit {
  loading = signal(true);
  error   = signal<string | null>(null);
  runs    = signal<RunSummary[]>([]);

  tableArchs = computed(() => {
    const runs = this.runs();
    return runs.length ? listArchs(runs[0]) : [];
  });

  constructor(private svc: RunsService) {}

  ngOnInit(): void {
    this.svc.getRuns().subscribe({
      next:  runs => { this.runs.set(runs); this.loading.set(false); },
      error: err  => { this.error.set(err.message ?? 'Failed to load runs'); this.loading.set(false); },
    });
  }

  pct       = fmtPct;
  cls       = asrClass;
  archLabel = archLabel;
  archRates = archRates;
}
