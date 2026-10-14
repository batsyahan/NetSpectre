// API token for devices other than the monitor's own machine (the monitor accepts local browsers without one).
// The token is kept in this browser only. The mobile app opens the dashboard as http://host:5173/#token=...
const KEY = "netspectre.apiToken";

export function getToken(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  try {
    if (token) localStorage.setItem(KEY, token);
    else localStorage.removeItem(KEY);
  } catch {
    /* storage blocked: the token then lasts only until reload */
  }
  memory = token;
}

let memory = "";
const current = () => getToken() || memory;

// Take a token passed in the address (#token=...) and remove it from the address bar and history.
export function takeTokenFromHash(): void {
  const m = window.location.hash.match(/token=([^&]+)/);
  if (!m) return;
  setToken(decodeURIComponent(m[1]));
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}

export const authHeaders = (): Record<string, string> => {
  const t = current();
  return t ? { "x-api-token": t } : {};
};

// For URLs that cannot carry headers (EventSource, download links).
export function withToken(url: string): string {
  const t = current();
  return t ? `${url}${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(t)}` : url;
}
