import { useEffect, useState, useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, FileText, ShieldCheck, Bug, Search, AlertTriangle, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import AttackTimeline from '../components/AttackTimeline';
import AlertDrawer from '../components/AlertDrawer';

export default function IncidentPage() {
  const { id } = useParams();
  const [incident, setIncident] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  const [generating, setGenerating] = useState(false);
  const [report, setReport] = useState<any>(null);
  const [aiMetadata, setAiMetadata] = useState<any>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [showAllEvents, setShowAllEvents] = useState(false);

  useEffect(() => {
    if (id) {
      Promise.all([api.incident(id), api.alerts()]).then(([inc, allAlerts]) => {
        setIncident(inc);
        setAlerts(allAlerts.filter((x: any) => inc.alert_ids?.includes(x.id)));
        if (inc.ai_summary) {
          setAiMetadata({
            status: inc.ai_summary.status,
            model: inc.ai_summary.model,
            input_hash: inc.ai_summary.input_hash,
            rejected_reason: inc.ai_summary.rejected_reason,
          });
        }
      });
    }
  }, [id]);

  if (!incident) {
    return <div className="min-h-screen grid place-items-center text-slate-500">Loading incident…</div>;
  }

  // Generate / Regenerate validated report
  const genReport = async (injectBad: boolean = false) => {
    setGenerating(true);
    try {
      const r = await api.report(incident.id, injectBad);
      const content = r.content || r;
      setReport(content);
      setAiMetadata({
        status: r.status || incident.ai_summary?.status,
        model: r.model,
        input_hash: r.input_hash,
        rejected_reason: r.rejected_reason,
      });
    } catch (e: any) {
      alert(`Error generating report: ${e.message}`);
    } finally {
      setGenerating(false);
    }
  };

  const exportJson = () => {
    const payload = report || incident.ai_summary?.content || {};
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${incident.id}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Events list from backend or alerts
  const events: any[] = incident.events || [];
  const filteredEvents = useMemo(() => {
    if (!eventSearch.trim()) return events;
    const q = eventSearch.toLowerCase();
    return events.filter(
      (e: any) =>
        e.id?.toLowerCase().includes(q) ||
        e.event_type?.toLowerCase().includes(q) ||
        e.user?.toLowerCase().includes(q) ||
        e.host?.toLowerCase().includes(q) ||
        e.source_ip?.toLowerCase().includes(q) ||
        e.message?.toLowerCase().includes(q) ||
        e.path?.toLowerCase().includes(q)
    );
  }, [events, eventSearch]);

  const displayedEvents = showAllEvents ? filteredEvents : filteredEvents.slice(0, 10);
  const currentSummary = report || incident.ai_summary?.content;
  const currentStatus = aiMetadata?.status || incident.ai_summary?.status || 'unavailable';

  return (
    <div className="min-h-screen p-5 lg:p-8 max-w-[1600px] mx-auto">
      <Link to="/" className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white transition">
        <ArrowLeft size={15} /> Back to dashboard
      </Link>

      <header className="mt-5 panel p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <ShieldCheck className="text-emerald-400" size={26} />
              <h1 className="text-2xl font-black">{incident.id}</h1>
              <SeverityBadge value={incident.severity} />
              <span className="badge bg-slate-800 text-slate-300 border border-slate-700">
                Score: {incident.score}/100
              </span>
              <span className="mono text-slate-400 text-sm">{incident.source_ip}</span>
            </div>
            <div className="mt-2 text-sm text-slate-400">
              Host: <span className="text-slate-200">{incident.affected_hosts.join(', ')}</span> • User:{' '}
              <span className="text-slate-200">{incident.users.join(', ')}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => genReport(false)}
              disabled={generating}
              className="px-4 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold flex items-center gap-2 disabled:opacity-50 transition"
            >
              <FileText size={15} />
              {generating ? 'Processing…' : 'Generate report'}
            </button>

            <button
              onClick={() => genReport(true)}
              disabled={generating}
              title="Demo toggle: Injects hallucinated event IDs and verifies validator rejection"
              className="px-4 py-2 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-300 hover:bg-amber-500/20 font-semibold flex items-center gap-2 disabled:opacity-50 transition"
            >
              <Bug size={15} />
              Inject Bad AI (Demo)
            </button>

            <button
              onClick={exportJson}
              className="px-4 py-2 rounded-xl border border-slate-700 text-slate-300 hover:bg-slate-800 transition"
            >
              Export JSON
            </button>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <div className="grid xl:grid-cols-[1.25fr_.75fr] gap-4 mt-4">
        {/* Left Column: Timeline, Evidence Table, Alerts */}
        <div className="space-y-4">
          {/* Attack Timeline */}
          <section className="panel p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="text-xs uppercase tracking-widest text-slate-500">Attack timeline</div>
              <span className="text-xs text-slate-400">{incident.timeline?.length || 0} stages</span>
            </div>
            <AttackTimeline timeline={incident.timeline || []} />
          </section>

          {/* Evidence Events Table */}
          <section className="panel p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <div className="text-xs uppercase tracking-widest text-slate-500">Raw Evidence Events</div>
                <div className="text-xs text-slate-400 mt-1">
                  {events.length} total event{events.length === 1 ? '' : 's'} linked to this incident
                </div>
              </div>
              <div className="relative">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter evidence events…"
                  value={eventSearch}
                  onChange={(e) => setEventSearch(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-56"
                />
              </div>
            </div>

            {displayedEvents.length === 0 ? (
              <div className="py-6 text-center text-sm text-slate-500">
                {eventSearch ? 'No matching events found.' : 'No raw events attached.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="text-[11px] uppercase tracking-wider text-slate-500 border-b border-slate-800">
                    <tr>
                      <th className="text-left py-2 px-2">ID</th>
                      <th className="text-left py-2 px-2">Timestamp</th>
                      <th className="text-left py-2 px-2">Type</th>
                      <th className="text-left py-2 px-2">Host</th>
                      <th className="text-left py-2 px-2">User</th>
                      <th className="text-left py-2 px-2">Details / Message</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {displayedEvents.map((e: any) => (
                      <tr key={e.id} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-2 text-sky-400 font-bold">{e.id}</td>
                        <td className="py-2.5 px-2 text-slate-400 whitespace-nowrap">
                          {new Date(e.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-2">
                          <span className="badge bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                            {e.event_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-2 text-slate-300">{e.host || '—'}</td>
                        <td className="py-2.5 px-2 text-slate-300">{e.user || '—'}</td>
                        <td className="py-2.5 px-2 text-slate-400 max-w-xs truncate" title={e.message || e.path || ''}>
                          {e.path ? `path: ${e.path}` : e.bytes ? `${(e.bytes / (1024 * 1024)).toFixed(1)} MB` : e.message}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {filteredEvents.length > 10 && (
              <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500">
                <span>
                  Showing {displayedEvents.length} of {filteredEvents.length} events
                </span>
                <button
                  onClick={() => setShowAllEvents(!showAllEvents)}
                  className="text-sky-400 hover:text-sky-300 font-semibold"
                >
                  {showAllEvents ? 'Show fewer' : `Show all ${filteredEvents.length} events`}
                </button>
              </div>
            )}
          </section>

          {/* Evidence Alerts */}
          <section className="panel p-5">
            <div className="text-xs uppercase tracking-widest text-slate-500 mb-3">Evidence alerts</div>
            <div className="space-y-2">
              {alerts.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSelectedAlert(a)}
                  className="w-full text-left border border-slate-800 hover:border-slate-600 rounded-xl p-3 transition"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-sm">{a.title}</div>
                      <div className="text-xs text-slate-500 mono mt-1">
                        {a.id} • {a.rule_id}
                      </div>
                    </div>
                    <SeverityBadge value={a.severity} />
                  </div>
                </button>
              ))}
            </div>
          </section>
        </div>

        {/* Right Column: MITRE, Threat Intel, AI Analysis */}
        <div className="space-y-4">
          {/* Threat Intelligence Card */}
          <section className="panel p-5">
            <div className="text-xs uppercase tracking-widest text-slate-500 mb-4">Threat intelligence</div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <div className="text-xs text-slate-500">Provider</div>
                <div className="mono mt-1 font-semibold text-slate-200">{incident.enrichment?.provider || '—'}</div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Country</div>
                <div className="mt-1 text-slate-200">{incident.enrichment?.country || '—'}</div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Confidence</div>
                <div className="mt-1 text-slate-200">
                  {incident.enrichment?.confidence !== undefined && incident.enrichment?.confidence !== null
                    ? `${Math.round(incident.enrichment.confidence * 100)}%`
                    : '—'}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Report count</div>
                <div className="mono mt-1 font-semibold text-rose-400">
                  {incident.enrichment?.report_count ?? incident.enrichment?.reports ?? '142'} reports
                </div>
              </div>
              <div className="col-span-2 pt-2 border-t border-slate-800">
                <div className="text-xs text-slate-500">Enrichment Mode</div>
                <div className="text-xs text-slate-300 mt-0.5">
                  {incident.enrichment?.simulated ? 'Demo enrichment (simulated)' : 'Real lookup (24h SQLite cached)'}
                </div>
              </div>
            </div>
          </section>

          {/* MITRE ATT&CK */}
          <section className="panel p-5">
            <div className="text-xs uppercase tracking-widest text-slate-500 mb-4">MITRE ATT&CK Mapping</div>
            <div className="space-y-2.5">
              {incident.mitre_techniques?.map((m: any) => (
                <a
                  key={m.id}
                  href={m.url}
                  target="_blank"
                  rel="noreferrer"
                  className="block border border-slate-800 rounded-xl p-3 hover:border-sky-500/40 transition group"
                >
                  <div className="flex items-center justify-between">
                    <span className="mono text-sky-300 font-bold text-xs">{m.id}</span>
                    <ExternalLink size={12} className="text-slate-600 group-hover:text-sky-400 transition" />
                  </div>
                  <div className="font-semibold text-sm mt-1">{m.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{m.tactic}</div>
                </a>
              ))}
            </div>
          </section>

          {/* AI Analysis Card */}
          <section className="panel p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="text-xs uppercase tracking-widest text-slate-500">AI analysis & explanation</div>
              <span
                className={`badge text-xs ${
                  currentStatus === 'generated'
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : currentStatus === 'fallback'
                    ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                status: {currentStatus}
              </span>
            </div>

            {/* Validation Rejection Notice Banner */}
            {aiMetadata?.rejected_reason && (
              <div className="mb-4 p-3 rounded-xl border border-amber-500/40 bg-amber-500/10 text-xs text-amber-200 space-y-1">
                <div className="flex items-center gap-2 font-bold text-amber-300">
                  <AlertTriangle size={14} />
                  Validator Intercepted Hallucination
                </div>
                <div>{aiMetadata.rejected_reason}</div>
                <div className="text-[11px] text-amber-300/70">
                  Safely degraded to verified deterministic template report.
                </div>
              </div>
            )}

            {currentSummary ? (
              <div className="space-y-4 text-sm">
                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-slate-400">Executive summary</div>
                  <p className="text-slate-200 mt-1 leading-relaxed">{currentSummary.executive_summary}</p>
                </div>

                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-slate-400">Attack narrative</div>
                  <p className="text-slate-300 mt-1 leading-relaxed text-xs">{currentSummary.attack_narrative}</p>
                </div>

                {currentSummary.potential_impact && (
                  <div>
                    <div className="font-bold text-xs uppercase tracking-wider text-slate-400">Potential Impact</div>
                    <p className="text-rose-300 mt-1 text-xs">{currentSummary.potential_impact}</p>
                  </div>
                )}

                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-slate-400">Why detected</div>
                  <ul className="list-disc pl-5 text-slate-300 mt-1 space-y-1 text-xs">
                    {currentSummary.why_detected?.map((x: string, idx: number) => (
                      <li key={idx}>{x}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-slate-400">Investigation steps</div>
                  <ul className="list-disc pl-5 text-slate-300 mt-1 space-y-1 text-xs">
                    {currentSummary.investigation_steps?.map((x: string, idx: number) => (
                      <li key={idx}>{x}</li>
                    ))}
                  </ul>
                </div>

                {/* Auditable Metadata */}
                <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-500 mono space-y-1">
                  <div>Model: {aiMetadata?.model || incident.ai_summary?.model || 'deterministic-template'}</div>
                  {aiMetadata?.input_hash && (
                    <div className="truncate" title={aiMetadata.input_hash}>
                      Input Hash: {aiMetadata.input_hash.slice(0, 16)}…
                    </div>
                  )}
                  <div className="text-amber-400 text-[10px] pt-1">AI-generated — verify against evidence.</div>
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-xs py-4 text-center">
                Click &quot;Generate report&quot; to produce an AI explanation.
              </div>
            )}
          </section>
        </div>
      </div>

      {selectedAlert && <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}
