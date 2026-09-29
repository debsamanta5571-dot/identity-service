import { DatePipe, JsonPipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, problemMessage } from '../core/api.service';
import { AuditEventDto, AuditFilter, Paged } from '../core/models';

@Component({
  selector: 'app-audit',
  imports: [FormsModule, DatePipe, JsonPipe],
  template: `
    <h1>Audit trail</h1>
    <p class="hint">Append-only. Entries cannot be changed or deleted, not even by this service.</p>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    <form class="toolbar wrap" (submit)="$event.preventDefault(); apply()">
      <label>Event <input name="eventType" list="types" placeholder="e.g. login.* or role.changed" [(ngModel)]="filter.eventType" /></label>
      <datalist id="types">
        @for (t of types; track t) { <option [value]="t"></option> }
      </datalist>
      <label>Outcome
        <select name="success" [(ngModel)]="filter.success">
          <option value="">Any</option><option value="true">Success</option><option value="false">Failure</option>
        </select>
      </label>
      <label>User id <input name="userId" [(ngModel)]="filter.userId" /></label>
      <label>IP <input name="ip" [(ngModel)]="filter.ip" /></label>
      <label>From <input name="from" type="datetime-local" [(ngModel)]="filter.from" /></label>
      <label>To <input name="to" type="datetime-local" [(ngModel)]="filter.to" /></label>
      <button type="submit">Filter</button>
      <button type="button" class="secondary" (click)="reset()">Reset</button>
    </form>

    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>User</th><th>Actor</th><th>IP</th><th>Details</th></tr></thead>
      <tbody>
        @for (e of data()?.items ?? []; track e.id) {
          <tr [class.fail]="!e.success">
            <td>{{ e.occurredAt | date: 'yyyy-MM-dd HH:mm:ss' }}</td>
            <td><code>{{ e.eventType }}</code></td>
            <td>{{ e.success ? 'ok' : 'failure' }}</td>
            <td class="mono">{{ e.userId }}</td>
            <td class="mono">{{ e.actorId }}</td>
            <td>{{ e.ipAddress }}</td>
            <td class="mono">{{ e.details ? (e.details | json) : '' }}</td>
          </tr>
        } @empty {
          <tr><td colspan="7">No matching events.</td></tr>
        }
      </tbody>
    </table>

    @if (data(); as d) {
      <p class="pager">
        <button type="button" class="secondary" [disabled]="d.page <= 1" (click)="go(d.page - 1)">Previous</button>
        Page {{ d.page }} of {{ pages(d) }} ({{ d.total }} events)
        <button type="button" class="secondary" [disabled]="d.page >= pages(d)" (click)="go(d.page + 1)">Next</button>
      </p>
    }
  `,
})
export class AuditPage implements OnInit {
  private readonly api = inject(ApiService);

  readonly data = signal<Paged<AuditEventDto> | null>(null);
  readonly error = signal('');
  filter: AuditFilter = { page: 1, pageSize: 25, success: '' };

  readonly types = [
    'login.*', 'login.success', 'login.failure', 'login.mfa_required', 'mfa.*', 'token.*', 'token.issued',
    'token.revoked', 'token.refresh_reuse_detected', 'user.*', 'role.changed', 'role.created', 'session.revoked',
  ];

  ngOnInit(): void {
    this.load();
  }

  pages = (d: Paged<AuditEventDto>) => Math.max(1, Math.ceil(d.total / d.pageSize));
  apply = () => this.go(1);
  reset(): void {
    this.filter = { page: 1, pageSize: 25, success: '' };
    this.load();
  }

  go(page: number): void {
    this.filter = { ...this.filter, page };
    this.load();
  }

  private load(): void {
    this.api.audit(this.filter).subscribe({
      next: (d) => { this.data.set(d); this.error.set(''); },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }
}
