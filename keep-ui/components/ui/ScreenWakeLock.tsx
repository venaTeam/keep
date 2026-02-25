"use client";

import { useEffect } from "react";

export default function WakeLock() {
  useEffect(() => {
    let wakeLock: WakeLockSentinel | null = null;

    const requestWakeLock = async () => {
      try {
        if ("wakeLock" in navigator) {
          wakeLock = await navigator.wakeLock.request("screen");
        }
      } catch (err: any) {
        console.error(`Wake Lock failed: ${err.name}, ${err.message}`);
      }
    };

    // Browsers often require a user gesture to acquire the lock.
    // If it fails initially, we try again on the first interaction.
    const handleInteraction = () => {
      if (!wakeLock || wakeLock.released) {
        requestWakeLock();
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        requestWakeLock();
      }
    };

    // Try immediately (might fail if no gesture yet)
    requestWakeLock();

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("click", handleInteraction);
    window.addEventListener("touchstart", handleInteraction);
    window.addEventListener("keydown", handleInteraction);

    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("click", handleInteraction);
      window.removeEventListener("touchstart", handleInteraction);
      window.removeEventListener("keydown", handleInteraction);

      if (wakeLock !== null) {
        wakeLock.release().catch(err => console.error("Failed to release lock", err));
        wakeLock = null;
      }
    };
  }, []);

  return null;
}
