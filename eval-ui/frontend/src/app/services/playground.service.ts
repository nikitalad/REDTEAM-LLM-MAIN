import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface AgentInfo {
  id:      string;
  label:   string;
  healthy: boolean;
}

export interface ToolCallLog {
  tool:               string;
  input:              Record<string, unknown>;
  result?:            string;
  blocked?:           boolean;
  reviewer_decision?: string;
  reviewer_reason?:   string;
}

export interface PlaygroundResponse {
  final_response: string;
  tool_calls:     ToolCallLog[];
  turn_count?:    number;
  turns?:         number;       // react/coder-reviewer use `turns`
  denied_count?:  number;
}

@Injectable({ providedIn: 'root' })
export class PlaygroundService {
  private http = inject(HttpClient);

  listAgents(): Observable<AgentInfo[]> {
    return this.http.get<AgentInfo[]>('/api/agents');
  }

  run(agent: string, task: string): Observable<PlaygroundResponse> {
    return this.http.post<PlaygroundResponse>('/api/playground/run', { agent, task });
  }
}
