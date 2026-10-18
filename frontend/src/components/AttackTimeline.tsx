import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle2 } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

interface TimelineItem {
  ts: string;
  stage: string;
  event_ids?: string[];
  description: string;
  mitre_id?: string;
  link_reason?: string;
  severity?: string;
  anomaly_score?: number | null;
}

export default function AttackTimeline({ timeline }: { timeline: TimelineItem[] }) {
  const getIconAndStyle = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return {
          icon: <ShieldAlert size={16} className="text-rose-400" />,
          circleClass: 'bg-rose-500/15 border-rose-500/30 text-rose-400',
        };
      case 'high':
        return {
          icon: <AlertTriangle size={16} className="text-amber-400" />,
          circleClass: 'bg-amber-500/15 border-amber-500/30 text-amber-400',
        };
      case 'medium':
        return {
          icon: <AlertCircle size={16} className="text-yellow-400" />,
          circleClass: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400',
        };
      case 'low':
        return {
          icon: <CheckCircle2 size={16} className="text-sky-400" />,
          circleClass: 'bg-sky-500/15 border-sky-500/30 text-sky-400',
        };
      default:
        return {
          icon: <CheckCircle2 size={16} className="text-emerald-400" />,
          circleClass: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400',
        };
    }
  };

  return (
    <div className="space-y-4">
      {timeline.map((x, i) => {
        const { icon, circleClass } = getIconAndStyle(x.severity);
        return (
          <div key={i} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div className={`w-8 h-8 rounded-full border grid place-items-center ${circleClass}`}>
                {icon}
              </div>
              {i < timeline.length - 1 && <div className="w-px h-16 bg-slate-700" />}
            </div>
            <div className="pb-3 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-500 mono">
                  {new Date(x.ts).toLocaleTimeString()}
                </span>
                <span className="text-sm font-bold capitalize">
                  {x.stage.replaceAll('_', ' ')}
                </span>
                {x.severity && <SeverityBadge value={x.severity} />}
                {x.mitre_id && (
                  <span className="badge bg-sky-500/10 text-sky-300 border border-sky-400/20">
                    {x.mitre_id}
                  </span>
                )}
                {x.anomaly_score !== undefined && x.anomaly_score !== null && (
                  <span className="badge bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs">
                    ⚡ Anomaly score: {typeof x.anomaly_score === 'number' ? `${Math.round(x.anomaly_score * 100)}%` : x.anomaly_score}
                  </span>
                )}
                {x.event_ids && x.event_ids.length > 0 && (
                  <span className="text-xs text-slate-500 mono">
                    ({x.event_ids.length} event{x.event_ids.length === 1 ? '' : 's'})
                  </span>
                )}
              </div>
              <div className="text-sm mt-1 text-slate-300">{x.description}</div>
              {x.link_reason && (
                <div className="text-xs text-slate-500 mt-1">
                  Pivot / Link: <span className="text-slate-400">{x.link_reason}</span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
