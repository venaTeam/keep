"use client";

import { useSSE } from "@/utils/hooks/useSSE";
import { ReactNode } from "react";

export function SSEProvider({ children }: { children: ReactNode }) {
    // This ensures the SSE connection is established globally
    // by calling useSSE at the top level
    useSSE();

    return <>{children}</>;
}
