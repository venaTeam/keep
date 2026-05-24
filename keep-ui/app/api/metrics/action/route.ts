import { NextRequest, NextResponse } from "next/server";
import { actionLatency, actionExecutions } from "@/metrics/metrics";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { label, latency } = body as { label?: string; latency?: number };

  if (!label || typeof latency !== "number") {
    return NextResponse.json(
      { error: "Missing or invalid 'label' or 'latency' field" },
      { status: 400 }
    );
  }

  actionLatency.observe({ action: label }, latency);
  actionExecutions.inc({ action: label });

  return NextResponse.json({ ok: true });
}