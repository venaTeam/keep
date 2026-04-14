
"use client";

import { useReportWebVitals } from "next/web-vitals";
import { usePathname } from "next/navigation";
import { recordWebVital } from "@/utils/otel-rum";

export function WebVitalsReporter() {
    const pathname = usePathname();

    useReportWebVitals((metric) => {
        // Sanitize path to avoid high cardinality labels
        // Example: /incidents/123 -> /incidents
        // Example: /settings/users -> /settings/users
        const parts = pathname?.split('/').filter(p => p);
        let safePath = "/";
        if (parts && parts.length > 0) {
            safePath = `/${parts[0]}`;
            // Exceptions for known safe 2nd levels
            if (parts[0] === 'settings' && parts.length > 1) {
                safePath = `/${parts[0]}/${parts[1]}`;
            }
        }

        // Record via OTEL SDK — exported directly to the OTEL Collector
        recordWebVital(metric.name, metric.value, safePath);
    });

    return null;
}
