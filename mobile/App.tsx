import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, FlatList, Platform, Pressable, StyleSheet, Text, View } from "react-native";
import { WebView } from "react-native-webview";
import { StatusBar } from "expo-status-bar";
import { API_TOKEN, API_URL, DASHBOARD_URL } from "./config";

interface Reason { feature: string; text: string; weight: number }
interface Alert {
  id: number; ts_utc: string; src_ip: string; label: string;
  flow_count: number; avg_confidence: number; status: string; explanation: Reason[];
}

const headers = { "x-api-token": API_TOKEN, "Content-Type": "application/json" };

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [online, setOnline] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"alerts" | "dashboard">("alerts");
  const [webError, setWebError] = useState("");
  const web = useRef<WebView>(null);
  const [webKey, setWebKey] = useState(0);

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API_URL}/api/alerts?limit=50`, { headers });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setAlerts(await r.json());
      setOnline(true);
      setError("");
    } catch (e) {
      setOnline(false);
      setError(`Cannot reach ${API_URL} (${String(e)})`);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load]);

  const setStatus = async (id: number, status: string) => {
    try {
      const r = await fetch(`${API_URL}/api/alerts/status`, {
        method: "POST", headers, body: JSON.stringify({ id, status }),
      });
      if (r.ok) setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
    } catch {}
  };

  const renderItem = ({ item: a }: { item: Alert }) => (
    <View style={[s.card, a.status === "dismissed" && s.dim]}>
      <View style={s.row}>
        <Text style={s.label}>{a.label}</Text>
        <Text style={s.conf}>{Math.round(a.avg_confidence * 100)}%</Text>
      </View>
      <Text style={s.meta}>{a.src_ip} · {a.flow_count} flows · {a.status}</Text>
      <Text style={s.meta}>{new Date(a.ts_utc).toLocaleString()}</Text>
      {a.explanation?.length > 0 && (
        <Text style={s.why}>Why: {a.explanation.map((r) => r.text).join("; ")}</Text>
      )}
      <View style={s.actions}>
        {a.status === "new" ? (
          <>
            <Pressable style={s.btn} onPress={() => setStatus(a.id, "acknowledged")}>
              <Text style={s.btnText}>Acknowledge</Text>
            </Pressable>
            <Pressable style={s.btn} onPress={() => setStatus(a.id, "dismissed")}>
              <Text style={s.btnText}>Dismiss</Text>
            </Pressable>
          </>
        ) : (
          <Pressable style={s.btn} onPress={() => setStatus(a.id, "new")}>
            <Text style={s.btnText}>Reopen</Text>
          </Pressable>
        )}
      </View>
    </View>
  );

  const newCount = alerts.filter((a) => a.status === "new").length;

  return (
    <View style={s.screen}>
      <StatusBar style="light" />
      <View style={s.header}>
        <Text style={s.title}>NetSpectre</Text>
        {tab === "dashboard" ? (
          <Pressable style={s.btn} onPress={() => { setWebError(""); setWebKey((k) => k + 1); web.current?.reload(); }}>
            <Text style={s.btnText}>Reload</Text>
          </Pressable>
        ) : (
          <Text style={[s.badge, online ? s.on : s.off]}>{online ? "Monitor online" : "Monitor offline"}</Text>
        )}
      </View>

      {/* Both tabs stay mounted so switching back does not reload the dashboard. */}
      <View style={[s.body, tab !== "alerts" && s.hidden]}>
        {error ? <Text style={s.empty}>{error}</Text> : null}
        <FlatList
          data={alerts}
          keyExtractor={(a) => String(a.id)}
          renderItem={renderItem}
          ListEmptyComponent={online ? <Text style={s.empty}>No alerts yet.</Text> : null}
        />
      </View>
      <View style={[s.body, s.webWrap, tab !== "dashboard" && s.hidden]}>
        {Platform.OS === "web" ? (
          // react-native-webview has no browser build; a plain iframe does the same job there.
          <iframe key={webKey} src={DASHBOARD_URL} style={{ flex: 1, border: 0, width: "100%", height: "100%" }} />
        ) : webError ? (
          <Text style={s.empty}>Cannot open {DASHBOARD_URL} ({webError}). Is the laptop on the same Wi-Fi and the dashboard running?</Text>
        ) : (
          <WebView
            ref={web}
            source={{ uri: DASHBOARD_URL }}
            style={s.web}
            startInLoadingState
            renderLoading={() => <ActivityIndicator style={s.loading} color="#60a5fa" />}
            onError={(e) => setWebError(e.nativeEvent.description || "load failed")}
            onHttpError={(e) => setWebError(`HTTP ${e.nativeEvent.statusCode}`)}
            pullToRefreshEnabled
            setSupportMultipleWindows={false}
          />
        )}
      </View>

      <View style={s.tabs}>
        <Pressable style={[s.tab, tab === "alerts" && s.tabOn]} onPress={() => setTab("alerts")}>
          <Text style={[s.tabText, tab === "alerts" && s.tabTextOn]}>Alerts{newCount ? ` (${newCount})` : ""}</Text>
        </Pressable>
        <Pressable style={[s.tab, tab === "dashboard" && s.tabOn]} onPress={() => setTab("dashboard")}>
          <Text style={[s.tabText, tab === "dashboard" && s.tabTextOn]}>Dashboard</Text>
        </Pressable>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#0e1217", paddingTop: 56 },
  body: { flex: 1, paddingHorizontal: 16 },
  hidden: { display: "none" },
  webWrap: { paddingHorizontal: 0 },
  web: { flex: 1, backgroundColor: "#0e1217" },
  loading: { position: "absolute", top: 40, alignSelf: "center" },
  tabs: { flexDirection: "row", borderTopWidth: 1, borderTopColor: "#2a313c", backgroundColor: "#11161d", paddingBottom: 24 },
  tab: { flex: 1, alignItems: "center", paddingVertical: 14 },
  tabOn: { borderTopWidth: 2, borderTopColor: "#60a5fa", marginTop: -1 },
  tabText: { color: "#8b95a7", fontSize: 14, fontWeight: "600" },
  tabTextOn: { color: "#e5e7eb" },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 16, paddingHorizontal: 16 },
  title: { color: "#fff", fontSize: 26, fontWeight: "700" },
  badge: { fontSize: 12, paddingHorizontal: 10, paddingVertical: 4, borderRadius: 12, overflow: "hidden" },
  on: { backgroundColor: "#12372a", color: "#34d399" },
  off: { backgroundColor: "#3b1a1a", color: "#f87171" },
  card: { backgroundColor: "#161b22", borderRadius: 10, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: "#2a313c" },
  dim: { opacity: 0.45 },
  row: { flexDirection: "row", justifyContent: "space-between" },
  label: { color: "#fff", fontSize: 17, fontWeight: "600" },
  conf: { color: "#60a5fa", fontSize: 15, fontWeight: "600" },
  meta: { color: "#8b95a7", fontSize: 13, marginTop: 3 },
  why: { color: "#a8b3c4", fontSize: 12, marginTop: 8, lineHeight: 17 },
  empty: { color: "#8b95a7", textAlign: "center", marginTop: 40 },
  actions: { flexDirection: "row", gap: 8, marginTop: 12 },
  btn: { backgroundColor: "#1f2937", borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8, borderWidth: 1, borderColor: "#2a313c" },
  btnText: { color: "#e5e7eb", fontSize: 13, fontWeight: "600" },
});
