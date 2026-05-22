import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Run, RunSummary } from '../models/run.model';

export interface SummaryEvent {
  text?: string;
  done?: boolean;
  error?: string;
}

@Injectable({ providedIn: 'root' })
export class RunsService {
  private http = inject(HttpClient);

  getRuns(): Observable<RunSummary[]> {
    return this.http.get<RunSummary[]>('/api/runs');
  }

  getLatestRun(): Observable<Run> {
    return this.http.get<Run>('/api/runs/latest');
  }

  getRun(id: string): Observable<Run> {
    return this.http.get<Run>(`/api/runs/${id}`);
  }

  getEgress(): Observable<Record<string, unknown>[]> {
    return this.http.get<Record<string, unknown>[]>('/api/egress');
  }

  getSummary(id: string): Observable<{ summary: string | null; cached: boolean }> {
    return this.http.get<{ summary: string | null; cached: boolean }>(`/api/runs/${id}/summary`);
  }

  // POST + SSE stream. Uses fetch() because EventSource only supports GET.
  generateSummary(id: string): Observable<SummaryEvent> {
    return new Observable(observer => {
      const controller = new AbortController();

      fetch(`/api/runs/${id}/summary/generate`, {
        method: 'POST',
        signal: controller.signal,
      }).then(async res => {
        if (!res.ok) {
          observer.error(new Error(`HTTP ${res.status}`));
          return;
        }
        const reader  = res.body!.getReader();
        const decoder = new TextDecoder();
        let   buf     = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop() ?? '';
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const event: SummaryEvent = JSON.parse(line.slice(6));
              observer.next(event);
              if (event.done || event.error) { observer.complete(); return; }
            } catch { /* malformed chunk — skip */ }
          }
        }
        observer.complete();
      }).catch(err => {
        if (err.name !== 'AbortError') observer.error(err);
      });

      return () => controller.abort();
    });
  }
}
