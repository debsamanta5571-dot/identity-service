import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthService);
  if ((await auth.getAccessToken()) !== null) return true;
  await auth.login(state.url);
  return false;
};
