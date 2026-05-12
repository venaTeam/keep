"use client";

import { useEffect } from "react";
import { startHeartbeat, startGlobalErrorTracking } from "@/utils/metrics";

export default function ActiveUsersTracker() {
  useEffect(() => {
    startHeartbeat();
    startGlobalErrorTracking();
  }, []);

  return null;
}