export interface AppConfig {
  apiUrl: string;
  clientId: string;
  scope: string;
}

let current: AppConfig | undefined;

/** Loaded from /config.json at startup so the same build can point at any environment. */
export async function loadConfig(): Promise<void> {
  const res = await fetch('config.json');
  if (!res.ok) throw new Error('config.json could not be loaded');
  const c = (await res.json()) as AppConfig;
  current = { ...c, apiUrl: c.apiUrl.replace(/\/$/, '') };
}

export function setConfig(c: AppConfig): void {
  current = c;
}

export function config(): AppConfig {
  if (!current) throw new Error('config not loaded');
  return current;
}
