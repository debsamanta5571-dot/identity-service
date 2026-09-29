import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';
import { AuditPage } from './pages/audit';
import { CallbackPage } from './pages/callback';
import { RolesPage } from './pages/roles';
import { SessionsPage } from './pages/sessions';
import { UsersPage } from './pages/users';

export const routes: Routes = [
  { path: 'auth/callback', component: CallbackPage },
  { path: 'users', component: UsersPage, canActivate: [authGuard] },
  { path: 'roles', component: RolesPage, canActivate: [authGuard] },
  { path: 'sessions', component: SessionsPage, canActivate: [authGuard] },
  { path: 'audit', component: AuditPage, canActivate: [authGuard] },
  { path: '', pathMatch: 'full', redirectTo: 'users' },
  { path: '**', redirectTo: 'users' },
];
