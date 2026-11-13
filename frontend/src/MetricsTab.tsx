import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { CircleHelp } from "lucide-react";
import type { Metrics } from "./types";

type Props = {
  metrics: Metrics | null;
  data: Array<{ name: string; precision: number; recall: number }>;
};

export default function MetricsTab({ metrics, data }: Props) {
  const accuracy = metrics?.reinsertion?.accuracy;
  const accuracyPct = typeof accuracy === "number" ? (accuracy <= 1 ? accuracy * 100 : accuracy) : null;

  return <div className="metrics-panel">
    <div className="panel-title-row"><div><h3>Gateway performance</h3><p>Evaluation metrics from the local synthetic-document report.</p></div><span className="report-source"><span className="status-dot" /> reports/metrics.json</span></div>
    {!metrics ? <div className="empty-tab"><CircleHelp size={18} />Metrics are unavailable. Start the API or regenerate the evaluation report.</div> : <>
      <div className="kpi-grid">
        <div className="kpi-card"><span>PII LEAKAGE</span><b className="kpi-green">{metrics.pii_leakage_count ?? "—"}</b><small>raw values found in outbound requests</small></div>
        <div className="kpi-card"><span>REINSERTION ACCURACY</span><b>{accuracyPct === null ? "—" : `${accuracyPct.toFixed(1)}%`}</b><small>{metrics.reinsertion?.restored_correctly ?? 0} / {metrics.reinsertion?.total_checked ?? 0} values restored</small></div>
        <div className="kpi-card"><span>P95 GATEWAY OVERHEAD</span><b>{metrics.latency_ms?.gateway_overhead_p95?.toFixed(2) ?? "—"}<small className="kpi-unit"> ms</small></b><small>not including model latency</small></div>
      </div>
      <div className="chart-card"><div className="chart-heading"><div><h4>Detection performance by entity type</h4><span>Precision and recall · percent</span></div><div className="chart-legend"><span><i className="legend-precision" /> Precision</span><span><i className="legend-recall" /> Recall</span></div></div>
        {data.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height={280}><BarChart data={data} margin={{ top: 8, right: 12, left: -20, bottom: 4 }} barGap={4}>
          <CartesianGrid stroke="rgba(145,159,195,.15)" vertical={false} /><XAxis dataKey="name" tick={{ fontSize: 10, fill: "#98a5c0" }} axisLine={false} tickLine={false} interval={0} /><YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#8794ae" }} axisLine={false} tickLine={false} tickFormatter={(value: number) => `${value}%`} /><Tooltip formatter={(value) => `${Number(value).toFixed(1)}%`} contentStyle={{ border: "1px solid rgba(145,159,195,.22)", borderRadius: 8, fontSize: 12, background: "#111827", color: "#e8edfa" }} /><Bar dataKey="precision" fill="#42d6a0" radius={[4, 4, 0, 0]} /><Bar dataKey="recall" fill="#9b8cff" radius={[4, 4, 0, 0]} />
        </BarChart></ResponsiveContainer></div> : <div className="empty-tab">Per-entity scores are not included in this report.</div>}
      </div>
    </>}
  </div>;
}
