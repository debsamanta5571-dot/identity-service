import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, problemMessage } from '../core/api.service';
import { Paged, RoleDto, UserDto } from '../core/models';

@Component({
  selector: 'app-users',
  imports: [FormsModule, DatePipe],
  template: `
    <h1>Users</h1>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }

    <form class="toolbar" (submit)="$event.preventDefault(); search()">
      <input name="q" [(ngModel)]="query" placeholder="Search email or name" aria-label="Search users" />
      <button type="submit">Search</button>
    </form>

    <table>
      <thead><tr><th>Email</th><th>Name</th><th>Roles</th><th>Status</th><th>MFA</th><th>Created</th><th></th></tr></thead>
      <tbody>
        @for (u of data()?.items ?? []; track u.id) {
          <tr>
            <td>{{ u.email }}</td>
            <td>{{ u.displayName }}</td>
            <td>
              @if (editing() === u.id) {
                @for (r of roles(); track r.id) {
                  <label class="inline">
                    <input type="checkbox" [checked]="draft().has(r.name)" (change)="toggleDraft(r.name)" /> {{ r.name }}
                  </label>
                }
                <button type="button" (click)="saveRoles(u)">Save</button>
                <button type="button" class="secondary" (click)="editing.set(null)">Cancel</button>
              } @else {
                {{ u.roles.join(', ') || '—' }}
              }
            </td>
            <td>
              {{ u.isActive ? 'Active' : 'Disabled' }}
              @if (isLocked(u)) { <span class="badge warn">Locked until {{ u.lockedUntil | date: 'short' }}</span> }
            </td>
            <td>{{ u.mfaEnabled ? 'On' : 'Off' }}</td>
            <td>{{ u.createdAt | date: 'yyyy-MM-dd' }}</td>
            <td class="actions">
              <button type="button" class="secondary" (click)="startEdit(u)">Roles</button>
              <button type="button" class="secondary" (click)="toggleActive(u)">{{ u.isActive ? 'Disable' : 'Enable' }}</button>
            </td>
          </tr>
        } @empty {
          <tr><td colspan="7">No users found.</td></tr>
        }
      </tbody>
    </table>

    @if (data(); as d) {
      <p class="pager">
        <button type="button" class="secondary" [disabled]="d.page <= 1" (click)="go(d.page - 1)">Previous</button>
        Page {{ d.page }} of {{ pages(d) }} ({{ d.total }} users)
        <button type="button" class="secondary" [disabled]="d.page >= pages(d)" (click)="go(d.page + 1)">Next</button>
      </p>
    }

    <h2>Create user</h2>
    <form class="stack" (submit)="$event.preventDefault(); create()">
      <label>Email <input name="email" type="email" required [(ngModel)]="form.email" /></label>
      <label>Display name <input name="displayName" required [(ngModel)]="form.displayName" /></label>
      <label>Initial password (min 12 characters) <input name="password" type="password" minlength="12" required [(ngModel)]="form.password" autocomplete="new-password" /></label>
      <fieldset>
        <legend>Roles</legend>
        @for (r of roles(); track r.id) {
          <label class="inline"><input type="checkbox" [checked]="form.roles.has(r.name)" (change)="toggleForm(r.name)" /> {{ r.name }}</label>
        }
      </fieldset>
      <button type="submit">Create user</button>
    </form>
  `,
})
export class UsersPage implements OnInit {
  private readonly api = inject(ApiService);
  private readonly pageSize = 10;

  readonly data = signal<Paged<UserDto> | null>(null);
  readonly roles = signal<RoleDto[]>([]);
  readonly error = signal('');
  readonly editing = signal<string | null>(null);
  readonly draft = signal<Set<string>>(new Set());
  query = '';
  form = { email: '', displayName: '', password: '', roles: new Set<string>() };

  ngOnInit(): void {
    this.api.roles().subscribe({ next: (r) => this.roles.set(r), error: (e) => this.error.set(problemMessage(e)) });
    this.load(1);
  }

  pages = (d: Paged<UserDto>) => Math.max(1, Math.ceil(d.total / d.pageSize));
  isLocked = (u: UserDto) => !!u.lockedUntil && new Date(u.lockedUntil) > new Date();
  search = () => this.load(1);
  go = (page: number) => this.load(page);

  private load(page: number): void {
    this.api.users(page, this.pageSize, this.query).subscribe({
      next: (d) => { this.data.set(d); this.error.set(''); },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }

  startEdit(u: UserDto): void {
    this.draft.set(new Set(u.roles));
    this.editing.set(u.id);
  }

  toggleDraft(name: string): void {
    const s = new Set(this.draft());
    s.has(name) ? s.delete(name) : s.add(name);
    this.draft.set(s);
  }

  toggleForm(name: string): void {
    this.form.roles.has(name) ? this.form.roles.delete(name) : this.form.roles.add(name);
  }

  saveRoles(u: UserDto): void {
    this.api.setUserRoles(u.id, [...this.draft()]).subscribe({
      next: () => { this.editing.set(null); this.load(this.data()?.page ?? 1); },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }

  toggleActive(u: UserDto): void {
    this.api.setUserActive(u.id, !u.isActive).subscribe({
      next: () => this.load(this.data()?.page ?? 1),
      error: (e) => this.error.set(problemMessage(e)),
    });
  }

  create(): void {
    this.api.createUser({ ...this.form, roles: [...this.form.roles] }).subscribe({
      next: () => {
        this.form = { email: '', displayName: '', password: '', roles: new Set() };
        this.error.set('');
        this.load(1);
      },
      error: (e) => this.error.set(problemMessage(e)),
    });
  }
}
