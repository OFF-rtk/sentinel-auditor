"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import Globe from "react-globe.gl";
import { LogEntry } from "@/app/page";

const SENTINEL_HQ = { lat: 19.0760, lng: 72.8777, name: "HQ", color: "#00ff41", size: 1.2 };

export default function HoloGlobe({ logs }: { logs: LogEntry[] }) {
  const globeEl = useRef<any>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Separate effect to initialize globe controls after it's mounted
  useEffect(() => {
    if (mounted && globeEl.current) {
      // Small delay to ensure globe is fully initialized
      const timer = setTimeout(() => {
        if (globeEl.current) {
          // Center the globe on SENTINEL_HQ (India)
          globeEl.current.pointOfView({ lat: SENTINEL_HQ.lat, lng: SENTINEL_HQ.lng, altitude: 2.5 }, 1000);
          globeEl.current.controls().autoRotate = true;
          globeEl.current.controls().autoRotateSpeed = 0.5;
        }
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [mounted]);


  const { points, arcs } = useMemo(() => {
    // Use lat/lng directly from audit log geo_location (populated by GeoLite2)
    const validLogs = logs.filter(l => {
      const geo = l.payload.network_context?.geo_location;
      return geo && geo.lat != null && geo.lng != null;
    });

    const mappedPoints = validLogs.map(log => {
      const geo = log.payload.network_context!.geo_location!;
      const isRisk = (log.payload.sentinel_analysis?.risk_score || 0) > 0.5;
      const country = geo.country || "??";
      const city = geo.city || "";

      return {
        lat: geo.lat,
        lng: geo.lng,
        name: city ? `${city}, ${country}` : country,
        color: isRisk ? "#ef4444" : "#22c55e",
        size: 0.5,
      };
    });

    const allPoints = [...mappedPoints, SENTINEL_HQ];

    const mappedArcs = mappedPoints.map(pt => ({
      startLat: pt.lat,
      startLng: pt.lng,
      endLat: SENTINEL_HQ.lat,
      endLng: SENTINEL_HQ.lng,
      color: pt.color,
      name: `${pt.name} → HQ`
    }));

    return { points: allPoints, arcs: mappedArcs };
  }, [logs]);

  if (!mounted) return <div className="text-green-501 animate-pulse p-10">INITALIZING_GEOSPATIAL_NET...</div>;

  return (
    <div className="h-full w-full flex items-center justify-center bg-transparent">
      <Globe
        ref={globeEl}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
        backgroundColor="rgba(0,0,0,0)"

        atmosphereColor="#00ff41"
        atmosphereAltitude={0.1}

        arcsData={arcs}
        arcColor="color"
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={2000}
        arcStroke={0.5}

        pointsData={points}
        pointLat="lat"
        pointLng="lng"
        pointColor="color"
        pointAltitude={0.01}
        pointRadius="size"

        labelsData={points}
        labelLat="lat"
        labelLng="lng"
        labelText="name"
        labelColor="color"
        labelDotRadius={0.3}
        labelSize={1.5}
        labelResolution={2}


        width={800}
        height={600}
      />
    </div>
  );
}
