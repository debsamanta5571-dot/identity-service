import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../core/auth.service';

@Component({
  selector: 'app-callback',
  template: `
    @if (error()) {
      <p class="error" role="alert">Sign-in failed: {{ error() }}</p>
      <button type="button" (click)="retry()">Try again</button>
    } @else {
      <p>Signing you in…</p>
    }
  `,
})
export class CallbackPage implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  readonly error = signal('');

  async ngOnInit(): Promise<void> {
    try {
      const returnUrl = await this.auth.handleCallback(new URLSearchParams(window.location.search));
      await this.router.navigateByUrl(returnUrl.startsWith('/') && !returnUrl.startsWith('//') ? returnUrl : '/');
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Unknown error');
    }
  }

  retry(): void {
    void this.auth.login('/');
  }
}
