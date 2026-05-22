import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  PlaygroundService,
  AgentInfo,
  PlaygroundResponse,
} from '../../services/playground.service';

@Component({
  selector: 'app-playground',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './playground.component.html',
  styleUrl: './playground.component.css',
})
export class PlaygroundComponent implements OnInit {
  agents          = signal<AgentInfo[]>([]);
  loadingAgents   = signal(true);
  agentsError     = signal<string | null>(null);

  selectedAgent   = signal<string>('');
  task            = signal<string>('');

  running         = signal(false);
  response        = signal<PlaygroundResponse | null>(null);
  error           = signal<string | null>(null);

  canSubmit = computed(() =>
    !this.running() && !!this.selectedAgent() && this.task().trim().length > 0,
  );

  turnCount = computed(() => {
    const r = this.response();
    return r ? (r.turn_count ?? r.turns ?? 0) : 0;
  });

  constructor(private svc: PlaygroundService) {}

  ngOnInit(): void {
    this.svc.listAgents().subscribe({
      next: agents => {
        this.agents.set(agents);
        const firstHealthy = agents.find(a => a.healthy) ?? agents[0];
        if (firstHealthy) this.selectedAgent.set(firstHealthy.id);
        this.loadingAgents.set(false);
      },
      error: err => {
        this.agentsError.set(err.message ?? 'Failed to load agents');
        this.loadingAgents.set(false);
      },
    });
  }

  selectAgent(id: string): void {
    this.selectedAgent.set(id);
  }

  submit(): void {
    if (!this.canSubmit()) return;
    this.running.set(true);
    this.response.set(null);
    this.error.set(null);

    this.svc.run(this.selectedAgent(), this.task()).subscribe({
      next: resp => {
        this.response.set(resp);
        this.running.set(false);
      },
      error: err => {
        this.error.set(err.error?.detail ?? err.message ?? 'Request failed');
        this.running.set(false);
      },
    });
  }

  prettyArgs(args: Record<string, unknown>): string {
    return JSON.stringify(args, null, 2);
  }
}
