"use client";

import { useCallback } from "react";
import { signOut } from "next-auth/react";
import * as Sentry from "@sentry/nextjs";
import { useConfig } from "@/utils/hooks/useConfig";

export function useSignOut() {
  const { data: configData } = useConfig();

  return useCallback(() => {
    if (!configData) {
      return;
    }

    if (configData?.SENTRY_DISABLED !== "true") {
      Sentry.setUser(null);
    }

    signOut();
  }, [configData]);
}
