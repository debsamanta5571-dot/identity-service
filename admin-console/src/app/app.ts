import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from './core/auth.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header>
      <strong>Identity admin</strong>
      @if (auth.user(); as user) {
        <nav aria-label="Main">
          <a routerLink="/users" routerLinkActive="active">Users</a>
          <a routerLink="/roles" routerLinkActive="active">Roles</a>
          <a routerLink="/sessions" routerLinkActive="active">Sessions</a>
          <a routerLink="/audit" routerLinkActive="active">Audit</a>
        </nav>
        <span class="who">{{ user.email }}</span>
        <button type="button" class="secondary" (click)="auth.logout()">Sign out</button>
      }
    </header>
    <main><router-outlet /></main>
  `,
})
export class App {
  protected readonly auth = inject(AuthService);
}
