import { StatusBar } from "expo-status-bar";
import { useCallback, useEffect, useState } from "react";
import { FlatList, RefreshControl, StyleSheet, Text, View } from "react-native";
import { API_TOKEN, API_URL } from "./config";

type Reason = { feature: string; text: string; weight: number };
type Alert = {
  id: number;
  ts_utc: string;
  src_ip: string;
  label: string;
  flow_count: number;
  avg_confidence: number;
  status: string;
  explanation?: Reason[];
};

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [online, setOnline] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API_URL}/api/alerts?limit=50`, { headers: { "x-api-token": API_TOKEN } });
      if (!r.ok) throw new Error("bad response");
      setAlerts(await r.json());
      setOnline(true);
    } catch {
      setOnline(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const onRefresh = async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  };

  return (
    <View style={s.screen}>
      <StatusBar style="light" />
      <View style={s.header}>
        <Text style={s.title}>NetSpectre</Text>
        <Text style={[s.badge, online ? s.on : s.off]}>{online ? "Monitor online" : "Monitor offline"}</Text>
      </View>
      <FlatList
        data={alerts}
        keyExtractor={(a) => String(a.id)}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#fff" />}
        ListEmptyComponent={
          <Text style={s.empty}>{online ? "No alerts yet. The network looks quiet." : `Cannot reach ${API_URL}`}</Text>
        }
        renderItem={({ item: a }) => (
          <View style={[s.card, a.status === "dismissed" && s.dim]}>
            <View style={s.row}>
              <Text style={s.label}>{a.label}</Text>
              <Text style={s.conf}>{Math.round(a.avg_confidence * 100)}%</Text>
            </View>
            <Text style={s.meta}>
              {a.src_ip} · {a.flow_count} flows · {a.status}
            </Text>
            <Text style={s.meta}>{new Date(a.ts_utc).toLocaleString("en-IN", { hour12: false })}</Text>
            {a.explanation && a.explanation.length > 0 && (
              <Text style={s.why}>
                Why: {a.explanation.map((r) => `${r.text} (${Math.round(r.weight)}%)`).join(", ")}
              </Text>
            )}
          </View>
        )}
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
});
