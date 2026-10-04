import { useCallback, useEffect, useState } from "react";
import { FlatList, Pressable, StyleSheet, Text, View } from "react-native";
import { StatusBar } from "expo-status-bar";
import { API_TOKEN, API_URL } from "./config";

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

  return (
    <View style={s.screen}>
      <StatusBar style="light" />
      <View style={s.header}>
        <Text style={s.title}>NetSpectre</Text>
        <Text style={[s.badge, online ? s.on : s.off]}>{online ? "Monitor online" : "Monitor offline"}</Text>
      </View>
      {error ? <Text style={s.empty}>{error}</Text> : null}
      <FlatList
        data={alerts}
        keyExtractor={(a) => String(a.id)}
        renderItem={renderItem}
        ListEmptyComponent={online ? <Text style={s.empty}>No alerts yet.</Text> : null}
      />
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#0e1217", paddingTop: 56, paddingHorizontal: 16 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 16 },
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
