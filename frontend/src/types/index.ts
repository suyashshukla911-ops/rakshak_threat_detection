export type Incident = {
  id:string; severity:string; score:number; status:string; source_ip:string; affected_hosts:string[]; users:string[]; alert_ids:string[]; stages:string[];
  timeline:{ts:string; stage:string; event_ids:string[]; description:string; mitre_id:string; link_reason:string}[];
  mitre_techniques:{id:string; name:string; tactic:string; url:string}[];
  enrichment:Record<string,any>; ai_summary:{status:string; content:any};
};
export type Alert = {id:string; rule_id:string; title:string; severity:string; confidence:number; event_ids:string[]; first_seen:string; last_seen:string; mitre_ids:string[]; explanation:any; anomaly_score:number|null; link_reason:string|null};
