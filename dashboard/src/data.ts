// Data hooks. One shared poller feeds every page; SSE "alert" events trigger an immediate reload.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchAlerts,
  fetchDevices,
  fetchHealth,
  fetchStats,
  postStatus,
  type Alert,
  type AlertStatus,
  type Device,
  type Stats,
} from "./api";

const POLL_MS = 10_000;
export const POLL_SECONDS = POLL_MS / 1000;

export interface Monitor {
  alerts: Alert[];
  devices: Device[];
  stats: Stats | null;
  online: boolean;
  loaded: boolean;
  stale: boolean;
  updated: Date | null;
  now: number;
  actionError: string | null;
  setStatus: (id: number, status: AlertStatus) => Promise<void>;
  clearActionError: () => void;
}

export function useMonitor(): Monitor {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [online, setOnline] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [stale, setStale] = useState(false);
  const [updated, setUpdated] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [actionError, setActionError] = useState<string | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    const [h, a, d, s] = await Promise.allSettled([fetchHealth(), fetchAlerts(), fetchDevices(), fetchStats()]);
    if (!alive.current) return;
    setOnline(h.status === "fulfilled" && h.value);
    if (a.status === "fulfilled") {
      setAlerts(a.value);
      setUpdated(new Date());
      setNow(Date.now());
    }
    if (d.status === "fulfilled") setDevices(d.value);
    // /api/stats is optional: an older monitor without it leaves stats null and the UI falls back.
    if (s.status === "fulfilled") setStats(s.value);
    setStale(a.status === "rejected" || d.status === "rejected");
    setLoaded(true);
  }, []);

  useEffect(() => {
    alive.current = true;
    void load();
    const es = new EventSource("/api/stream");
    es.addEventListener("alert", () => {
      void load();
    });
    const timer = setInterval(() => {
      void load();
    }, POLL_MS);
    return () => {
      alive.current = false;
      es.close();
      clearInterval(timer);
    };
  }, [load]);

  const setStatus = useCallback(
    async (id: number, status: AlertStatus) => {
      try {
        await postStatus(id, status);
        setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
        void load();
      } catch {
        setActionError(`Could not update alert ${id}. Check that the monitor is reachable and try again.`);
      }
    },
    [load],
  );

  const clearActionError = useCallback(() => setActionError(null), []);

  return { alerts, devices, stats, online, loaded, stale, updated, now, actionError, setStatus, clearActionError };
}

// Full alert history for one device (the shared list only holds the newest 500 across all devices).
export function useDeviceAlerts(ip: string, refreshKey: number) {
  const [rows, setRows] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!ip) {
      setRows([]);
      setFailed(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    fetchAlerts(500, ip)
      .then((r) => {
        if (!cancelled) {
          setRows(r);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ip, refreshKey]);

  return { rows, loading, failed };
}
