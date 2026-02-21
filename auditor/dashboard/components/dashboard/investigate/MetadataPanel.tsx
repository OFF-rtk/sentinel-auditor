"use client";

import { User, MapPin, Globe, CreditCard, ShieldAlert, Clock, Fingerprint, Activity } from "lucide-react";

export default function MetadataPanel({ log }: { log: any }) {
    if (!log) return null;

    // Destructure safely based on your provided JSON
    const { actor, network_context, action_context, sentinel_analysis } = log.payload;

    return (
        <div className="h-full w-80 bg-[#09090b] border-r border-zinc-800 flex flex-col z-20 shadow-2xl overflow-y-auto scrollbar-dark">

            {/* Header: Actor */}
            <div className="p-6 border-b border-zinc-800 bg-zinc-900/50">
                <h2 className="text-[10px] font-bold text-zinc-500 tracking-widest uppercase mb-2">Target Identity</h2>
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-zinc-800 rounded-lg text-zinc-200 border border-zinc-700">
                        <User size={20} />
                    </div>
                    <div>
                        <div className="text-lg font-bold text-white tracking-tight">{actor?.user_id || "Unknown"}</div>
                        <div className="flex gap-2 mt-1">
                            <span className="text-[9px] text-zinc-400 font-bold bg-zinc-800 px-1.5 py-0.5 rounded border border-zinc-700 uppercase">
                                {actor?.role}
                            </span>
                            {actor?.session_age_seconds && (
                                <span className="text-[9px] text-zinc-500 font-mono py-0.5">
                                    {Math.floor(actor.session_age_seconds / 60)}m active
                                </span>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Section: Network Intelligence */}
            <div className="p-6 border-b border-zinc-800">
                <h3 className="flex items-center gap-2 text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">
                    <Globe size={12} className="text-blue-500" /> Network Context
                </h3>

                <div className="space-y-4">
                    {/* Geolocation */}
                    <div className="group">
                        <label className="text-[10px] text-zinc-600 block mb-1">Geolocation</label>
                        <div className="flex items-center gap-2 text-sm text-zinc-300 font-mono">
                            <MapPin size={14} className="text-zinc-500" />
                            {network_context?.geo_location?.city}, {network_context?.geo_location?.country}
                        </div>
                    </div>

                    {/* IP Address */}
                    <div>
                        <label className="text-[10px] text-zinc-600 block mb-1">IP Address</label>
                        <div className="flex items-center justify-between p-2 bg-zinc-900 rounded border border-zinc-800">
                            <span className="text-xs text-blue-400 font-mono">{network_context?.ip_address}</span>
                        </div>
                    </div>

                    {/* Device ID */}
                    <div>
                        <label className="text-[10px] text-zinc-600 block mb-1">Device ID</label>
                        <div className="text-[10px] text-zinc-500 font-mono break-all bg-zinc-900/30 p-1 rounded border border-zinc-800/50">
                            <Fingerprint size={10} className="inline mr-1 text-zinc-600" />
                            {network_context?.client_fingerprint?.device_id || "N/A"}
                        </div>
                    </div>

                    {/* User Agent */}
                    <div>
                        <label className="text-[10px] text-zinc-600 block mb-1">User Agent</label>
                        <div className="text-[10px] text-zinc-500 font-mono break-all bg-zinc-900/30 p-1 rounded border border-zinc-800/50">
                            {network_context?.client_fingerprint?.user_agent || "N/A"}
                        </div>
                    </div>
                </div>
            </div>

            {/* Section: Action Payload */}
            <div className="p-6 border-b border-zinc-800">
                <h3 className="flex items-center gap-2 text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">
                    <Activity size={12} className="text-green-500" /> Action Payload
                </h3>

                <div className="bg-zinc-900/50 rounded-lg p-3 border border-zinc-800 space-y-3">
                    <div className="flex justify-between items-center pb-2 border-b border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase">Service</span>
                        <span className="text-xs text-white font-bold">{action_context?.service}</span>
                    </div>
                    <div className="flex justify-between items-center pb-2 border-b border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase">Type</span>
                        <span className="text-xs text-white font-bold">{action_context?.action_type}</span>
                    </div>

                    {/* 🟢 SPECIFIC FIELDS FOR YOUR LOG STRUCTURE */}
                    {action_context?.details?.amount && (
                        <div className="flex justify-between items-center pt-1">
                            <span className="text-[10px] text-zinc-500 uppercase">Amount</span>
                            <div className="flex items-center gap-1 text-green-400 font-mono font-bold">
                                <CreditCard size={12} />
                                {action_context.details.currency} {action_context.details.amount}
                            </div>
                        </div>
                    )}
                    {action_context?.resource_target && (
                        <div className="flex justify-between items-center pt-1">
                            <span className="text-[10px] text-zinc-500 uppercase">Target</span>
                            <span className="text-[10px] text-zinc-400 font-mono">{action_context.resource_target}</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Section: Sentinel Snapshot */}
            <div className="p-6 bg-gradient-to-b from-zinc-900/0 to-zinc-900/50 flex-1">
                <h3 className="flex items-center gap-2 text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">
                    <ShieldAlert size={12} className="text-orange-500" /> Initial Vector
                </h3>

                <div className="grid grid-cols-2 gap-2 mb-4">
                    <div className="bg-zinc-900 p-2 rounded border border-zinc-800 text-center">
                        <div className="text-[9px] text-zinc-600 uppercase">Risk Score</div>
                        <div className={`text-xl font-bold font-mono ${sentinel_analysis?.risk_score > 0.7 ? 'text-red-500' : 'text-green-500'}`}>
                            {sentinel_analysis?.risk_score ?? 0}
                        </div>
                    </div>
                    <div className="bg-zinc-900 p-2 rounded border border-zinc-800 text-center">
                        <div className="text-[9px] text-zinc-600 uppercase">Anomalies</div>
                        <div className="text-xl font-bold font-mono text-zinc-200">
                            {sentinel_analysis?.anomaly_vectors?.length || 0}
                        </div>
                    </div>
                </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-zinc-800 text-[10px] text-zinc-600 font-mono flex items-center gap-2 justify-center">
                <Clock size={10} />
                {new Date(log.created_at).toLocaleString()}
            </div>
        </div>
    );
}