"use client";

import { useEffect, useState, useMemo } from "react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { supabase } from "@/lib/supabaseClient"
import LogFeed from "@/components/dashboard/LogFeed";

const HoloGlobe = dynamic(() => import("@/components/dashboard/HoloGlobe"), {
  ssr: false,
  loading: () => <div className="text-green-500 font-mono p-10">LOADING MODULE...</div>
});

export type LogPayload = {
  event_id: string;
  timestamp: string;
  environment: string;
  correlation_id: string;

  actor: {
    user_id: string;
    role: string;
    session_id?: string;
    session_age_seconds?: number;
  };

  action_context?: {
    service: string;
    action_type: string;
    resource_target?: string;
    details?: {
      amount?: number;
      currency?: string;
      recipient_country?: string;
      [key: string]: any;
    }
  };

  network_context: {
    ip_address: string;
    geo_location?: {
      asn?: string;
      city?: string;
      country: string;
    };
    ip_reputation?: string;
    client_fingerprint?: {
      ja3_hash?: string;
      user_agent_raw?: string;
      device_id?: string;
    };
  };

  sentinel_analysis: {
    decision: string;
    risk_score: number;
    engine_version?: string;
    anomaly_vectors: string[];
  }

  security_enforcement?: {
    mfa_status?: string;
    policy_applied?: string;
  };
};

export type LogEntry = {
  id: number;
  created_at: string;
  payload: LogPayload;
};

export default function Home() {
  const router = useRouter();
  const [logsMap, setLogsMap] = useState<Map<string, LogEntry>>(new Map());

  const logs = useMemo(() => {
    return Array.from(logsMap.values()).sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    ).slice(0, 25);
  }, [logsMap]);

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  };

  useEffect(() => {
    const fetchInitial = async () => {
      const { data } = await supabase
        .from("audit_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(25);
      if (data) {
        setLogsMap((prev) => {
          const newMap = new Map(prev);
          data.forEach((log) => {
            // Only add if not already present
            if (!newMap.has(log.payload.event_id)) {
              newMap.set(log.payload.event_id, log);
            }
          });
          return newMap;
        });
      }
    };
    fetchInitial();

    const channel = supabase
      .channel("matrix-feed")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "audit_logs" },
        (payload) => {
          const newLog = payload.new as LogEntry;
          setLogsMap((prev) => {
            // Skip if already exists
            if (prev.has(newLog.payload.event_id)) return prev;
            const newMap = new Map(prev);
            newMap.set(newLog.payload.event_id, newLog);
            return newMap;
          });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    }
  }, []);

  const activeThreats = logs.filter(l => (l.payload.sentinel_analysis?.risk_score || 0) > 0.5).length;

  return (
    <main className="flex h-screen flex-col bg-black font-mono text-green-500 overflow-hidden">

      <header className="w-full p-4 border-b border-green-900/30 flex justify-between items-center bg-black/80 backdrop-blur z-50 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tighter text-white">SENTINEL <span className="text-green-500">AUDITOR</span></h1>
          <p className="text-xs text-zinc-500">REAL-TIME THREAT MONITORING // V1.0</p>
        </div>
        <div className="flex gap-4 text-xs items-center">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse"></span>
            SYSTEM ONLINE
          </div>
          <div className="flex items-center gap-2">
            <span className="text-zinc-500">ACTIVE THREATS:</span>
            <span className="text-red-500 font-bold">{activeThreats}</span>
          </div>
          <button
            onClick={handleSignOut}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-zinc-700 hover:border-red-500/50 hover:bg-red-500/10 text-zinc-400 hover:text-red-400 transition-all cursor-pointer"
            title="Sign Out"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>SIGN OUT</span>
          </button>
        </div>
      </header>


      <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-0 relative min-h-0">

        <div className="hidden md:block h-full overflow-y-auto border-r border-green-900/30 scrollbar-dark">
          <LogFeed logs={logs} />
        </div>

        <div className="col-span-2 relative flex items-center justify-center overflow-hidden bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-zinc-900 to-black">
          <div className="absolute inset-0 z-0 flex items-center justify-center">
            <HoloGlobe logs={logs} />
          </div>

          <div className="absolute inset-0 z-10 pointer-events-none bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-10"></div>
        </div>
      </div>
    </main>
  );
}
