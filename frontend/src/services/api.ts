const API = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

async function req<T>(path:string, opts?:RequestInit):Promise<T>{
  const r=await fetch(`${API}${path}`, opts); if(!r.ok) throw new Error(await r.text()); return r.json();
}
export const api={
  health:()=>req<any>('/health'), stats:()=>req<any>('/stats'), incidents:()=>req<any[]>('/incidents'), incident:(id:string)=>req<any>(`/incidents/${id}`), alerts:()=>req<any[]>('/alerts'), alert:(id:string)=>req<any>(`/alerts/${id}`),
  run:()=>req<{run_id:string}>('/simulation/run',{method:'POST'}), status:(id:string)=>req<any>(`/simulation/${id}/status`), reset:()=>req<any>('/simulation/reset',{method:'POST'}), report:(id:string)=>req<any>(`/incidents/${id}/report`,{method:'POST'}), upload:(file:File)=>{const f=new FormData();f.append('file',file);return req<any>('/logs/upload',{method:'POST',body:f})}
};
