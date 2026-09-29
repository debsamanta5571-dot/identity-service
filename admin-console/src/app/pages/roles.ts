import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, problemMessage } from '../core/api.service';
import { RoleDto, ScopeDto } from '../core/models';

@Component({
  selector: 'app-roles',
  imports: [FormsModule],
  template: `
    <h1>Roles and scopes</h1>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    <table>
      <thead><tr><th>Role</th><th>Description</th><th>Scopes</th></tr></thead>
      <tbody>
        @for (r of roles(); track r.id) {
          <tr><td>{{ r.name }}</td><td>{{ r.description }}</td><td><code>{{ r.scopes.join(' ') || '—' }}</code></td></tr>
        }
      </tbody>
    </table>

    <h2>Create role</h2>
    <form class="stack" (submit)="$event.preventDefault(); create()">
      <label>Name (lowercase, digits, hyphens) <input name="name" required pattern="[a-z][a-z0-9-]{1,49}" [(ngModel)]="form.name" /></label>
      <label>Description <input name="description" [(ngModel)]="form.description" /></label>
      <fieldset>
        <legend>Scopes</legend>
        @for (s of scopes(); track s.name) {
          <label class="inline" [title]="s.description">
            <input type="checkbox" [checked]="form.scopes.has(s.name)" (change)="toggle(s.name)" /> {{ s.name }}
          </label>
        }
      </fieldset>
      <button type="submit">Create role</button>
    </form>
  `,
})
export class RolesPage implements OnInit {
  private readonly api = inject(ApiService);
  readonly roles = signal<RoleDto[]>([]);
  readonly scopes = signal<ScopeDto[]>([]);
  readonly error = signal('');
  form = { name: '', description: '', scopes: new Set<string>() };

  ngOnInit(): void {
    this.reload();
    this.api.scopes().subscribe({ next: (s) => this.scopes.set(s), error: (e) => this.error.set(problemMessage(e)) });
  }

  private reload(): void {
    this.api.roles().subscribe({ next: (r) => this.roles.set(r), error: (e) => this.error.set(problemMessage(e)) });
  }

  toggle(name: string): void {
    this.form.scopes.has(name) ? this.form.scopes.delete(name) : this.form.scopes.add(name);
  }

  create(): void {
    this.api.createRole({ ...this.form, scopes: [...this.form.scopes] }).subscribe({
      next: () => { this.form = { name: '', description: '', scopes: new Set() }; this.error.set(''); this.reload(); },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }
}
