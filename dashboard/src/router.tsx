// A very small History API router. nginx already falls back to index.html for unknown paths,
// so these routes also work on a hard refresh.
import { useSyncExternalStore, type MouseEvent, type ReactNode } from "react";

function subscribe(callback: () => void) {
  window.addEventListener("popstate", callback);
  return () => window.removeEventListener("popstate", callback);
}
const snapshot = () => window.location.pathname + window.location.search;

export function useLocation() {
  const s = useSyncExternalStore(subscribe, snapshot);
  const [path, query = ""] = s.split("?");
  return { path: path || "/", params: new URLSearchParams(query) };
}

export function navigate(to: string) {
  if (snapshot() === to) return;
  window.history.pushState(null, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo(0, 0);
}

export function Link({
  to,
  children,
  className,
  current,
}: {
  to: string;
  children: ReactNode;
  className?: string;
  current?: boolean;
}) {
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} className={className} onClick={onClick} aria-current={current ? "page" : undefined}>
      {children}
    </a>
  );
}
