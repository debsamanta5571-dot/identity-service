import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { config } from './config';

/** Adds the bearer token to calls to our API; a 401 sends the user back through sign-in. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(config().apiUrl)) return next(req);
  const auth = inject(AuthService);

  return from(auth.getAccessToken()).pipe(
    switchMap((token) => {
      if (!token) {
        void auth.login(window.location.pathname);
        return throwError(() => new HttpErrorResponse({ status: 401, statusText: 'Signed out' }));
      }
      return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
    }),
    catchError((e: unknown) => {
      if (e instanceof HttpErrorResponse && e.status === 401) void auth.login(window.location.pathname);
      return throwError(() => e);
    }),
  );
};
