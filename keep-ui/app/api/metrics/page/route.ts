import { NextRequest, NextResponse } from "next/server";
import { pageloadLatency, pageloads } from "@/metrics/metrics";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { label, latency } = body as { label?: string; latency?: number };

  if (!label || typeof latency !== "number") {
    return NextResponse.json(
      { error: "Missing or invalid 'label' or 'latency' field" },
      { status: 400 }
    );
  }

  pageloadLatency.observe({ page: label }, latency);
  pageloads.inc({ page: label });

  return NextResponse.json({ ok: true });
}