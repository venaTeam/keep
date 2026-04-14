"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { reportError, reportHeartbeat } from "@/utils/otel-rum";

export default function GlobalMetrics() {
    const pathname = usePathname();

    useEffect(() => {
        // 1. Global Error Tracking
        const handleError = (event: ErrorEvent) => {
            reportError("window-error", event.message, pathname);
        };

        const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
            const message = event.reason?.message || "Unhandled Promise Rejection";
            reportError("unhandled-rejection", message, pathname);
        };

        window.addEventListener("error", handleError);
        window.addEventListener("unhandledrejection", handleUnhandledRejection);

        // 2. Heartbeat (Active Users)
        // Report once on mount/pathname change
        reportHeartbeat(pathname);

        // Then interval every 30 seconds
        const interval = setInterval(() => {
            reportHeartbeat(pathname);
        }, 30000);

        return () => {
            window.removeEventListener("error", handleError);
            window.removeEventListener("unhandledrejection", handleUnhandledRejection);
            clearInterval(interval);
        };
    }, [pathname]);

    return null;
}
