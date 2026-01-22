
"use client";

import { useReportWebVitals } from "next/web-vitals";
import { usePathname } from "next/navigation";

export function WebVitalsReporter() {
    const pathname = usePathname();

    useReportWebVitals((metric) => {
        // Basic sanitation to avoid high cardinality labels
        // We group dynamic routes if possible, but usePathname usually returns the resolved path.
        // Ideally, we should use the route pattern (e.g. /incidents/[id]), but that's harder to get in app router client components reliably without more plumbing.
        // For now, let's take the first segment as a crude grouping if it's an ID-like string, or just trust the path.
        // Actually, to be safe for Prometheus, let's just use the top-level path segment for now.

        // Example: /incidents/123 -> /incidents
        // Example: /settings -> /settings
        // Example: / -> /

        const parts = pathname?.split('/').filter(p => p);
        let safePath = "/";
        if (parts && parts.length > 0) {
            safePath = `/${parts[0]}`;
            // Exceptions for known safe 2nd levels
            if (parts[0] === 'settings' && parts.length > 1) {
                safePath = `/${parts[0]}/${parts[1]}`;
            }
        }

        const body = JSON.stringify({
            ...metric,
            path: safePath,
        });

        const url = "/api/rum";

        // Use `navigator.sendBeacon()` if available, falling back to `fetch()`.
        if (navigator.sendBeacon) {
            navigator.sendBeacon(url, body);
        } else {
            fetch(url, { body, method: "POST", keepalive: true });
        }
    });

    return null;
}
