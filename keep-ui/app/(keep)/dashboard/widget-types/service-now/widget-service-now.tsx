import React, { useEffect, useMemo, useState } from "react";
import { Threshold } from "../../types";
import { Button } from "@tremor/react";
import Skeleton from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { useApi } from "@/shared/lib/hooks/useApi";
import useSWR from "swr";

interface WidgetServiceNowProps {
  background?: string;
  thresholds?: Threshold[];
  team?: string;
  status?: "open" | "in_progress" | "both";
  detection?: "direct" | "hamal" | "all";
  customLink?: string;
}

const WidgetServiceNow: React.FC<WidgetServiceNowProps> = ({
  background,
  thresholds = [],
  team,
  status = "both",
  detection = "all",
  customLink,
}) => {
  const api = useApi();
  const [count, setCount] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const params = useMemo(() => {
    const stateParam = status === "both" ? "all" : status === "open" ? "new" : "in_progress";
    const query = new URLSearchParams();
    if (team) query.set("team", team);
    if (stateParam) query.set("state", stateParam);
    if (detection && detection !== "all") {
      query.set("detection", detection);
    }
    const qs = query.toString();
    return qs ? `?${qs}` : "";
  }, [team, status, detection]);

  const { data, error: swrError } = useSWR<any>(
    api.isReady() ? `/dashboard/ticket-count${params}` : null,
    (url: string) => api.get(url),
    {
      refreshInterval: 60000, // Refresh every 60 seconds
      revalidateOnFocus: true,
    }
  );

  useEffect(() => {
    if (data) {
      if (typeof data.count === "number") {
        setCount(data.count);
        setError(null);
      } else if (typeof data === "object" && data && "Team not found" in data) {
        setCount(0);
        setError(null);
      } else {
        setError("error getting information");
        setCount(null);
      }
      setIsLoading(false);
    } else if (swrError) {
      setIsLoading(false);
      setError("error getting information");
    }
  }, [data, swrError]);

  const getColor = (count: number) => {
    let color = "#1f2937"; // Default dark gray
    if (thresholds && thresholds.length > 0) {
      for (let i = thresholds.length - 1; i >= 0; i--) {
        if (count >= thresholds[i].value) {
          color = thresholds[i].color;
          break;
        }
      }
    }
    return color;
  };

  function hexToRgb(hex: string, alpha: number = 1) {
    hex = hex.replace(/^#/, "");
    if (hex.length === 3) {
      hex = hex
        .split("")
        .map((c) => c + c)
        .join("");
    }
    const bigint = parseInt(hex, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgb(${r}, ${g}, ${b}, ${alpha})`;
  }

  const displayCount = isLoading ? "..." : count ?? 0;
  const color = count !== null ? getColor(count) : "#1f2937";

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2 flex-shrink-0">
        <div className="text-sm font-medium text-gray-700 h-4">Service Now</div>
        <div className="flex items-center space-x-1">
          {customLink && (
            <Button
              color="blue"
              variant="secondary"
              size="xs"
              onClick={() => window.open(customLink, "_blank")}
            >
              Go to Link
            </Button>
          )}
        </div>
      </div>
      <div
        style={{
          background: hexToRgb(color, 0.15),
          borderColor: color,
          borderWidth: "2px",
        }}
        className="max-w-full border rounded-lg p-2 h-full shadow-sm"
      >
        <div className="flex-1 flex flex-col justify-center min-h-0">
          <div className="flex flex-col space-y-2 items-center">
            {!error && (
              <div className="text-xs text-gray-500">
                {team ? `Team: ${team} • ` : ""}State: {status === "both" ? "all" : status} • Detection: {detection}
              </div>
            )}
            <div
              className="text-4xl font-black tracking-tight"
              style={{
                color,
                textShadow: `0 1px 2px rgba(0,0,0,0.1)`,
              }}
            >
              {error ? (
                <span className="text-black">{error}</span>
              ) : isLoading ? (
                <Skeleton containerClassName="h-8 w-16" />
              ) : (
                displayCount
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WidgetServiceNow;

