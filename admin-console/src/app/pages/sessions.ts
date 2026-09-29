import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { ApiService, problemMessage } from '../core/api.service';
import { SessionDto } from '../core/models';

@Component({
  selector: 'app-sessions',
  imports: [DatePipe],
  template: `
    <h1>Active sessions</h1>
    <p class="hint">
      A session is one sign-in (a refresh-token family). Revoking it stops new tokens being issued; access tokens
      already issued keep working until they expire (minutes).
    </p>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    <table>
      <thead><tr><th>User</th><th>Client</th><th>Signed in</th><th>Expires</th><th></th></tr></thead>
      <tbody>
        @for (s of sessions(); track s.id) {
          <tr>
            <td>{{ s.email ?? s.userId }}</td>
            <td>{{ s.clientId }}</td>
            <td>{{ s.createdAt | date: 'medium' }}</td>
            <td>{{ s.expiresAt | date: 'medium' }}</td>
            <td><button type="button" class="secondary" (click)="revoke(s)">Revoke</button></td>
          </tr>
        } @empty {
          <tr><td colspan="5">No active sessions.</td></tr>
        }
      </tbody>
    </table>
    <button type="button" class="secondary" (click)="load()">Refresh</button>
  `,
})
export class SessionsPage implements OnInit {
  private readonly api = inject(ApiService);
  readonly sessions = signal<SessionDto[]>([]);
  readonly error = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.sessions().subscribe({
      next: (s) => { this.sessions.set(s); this.error.set(''); },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }

  revoke(s: SessionDto): void {
    if (!window.confirm(`Revoke this session for ${s.email ?? s.userId}?`)) return;
    this.api.revokeSession(s.id).subscribe({ next: () => this.load(), error: (e) => this.error.set(problemMessage(e)) });
  }
}
