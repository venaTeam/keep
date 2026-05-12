import { NextRequest, NextResponse } from "next/server";
import { errors } from "@/metrics/metrics";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { action } = body as { action?: string };

  if (!action) {
    return NextResponse.json({ error: "Missing 'action' field" }, { status: 400 });
  }

  errors.inc({ action });

  return NextResponse.json({ ok: true });
}