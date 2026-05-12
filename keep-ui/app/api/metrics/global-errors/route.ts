import { NextRequest, NextResponse } from "next/server";
import { globalErrors } from "@/metrics/metrics";

export async function POST(req: NextRequest) {
  globalErrors.inc();
  return NextResponse.json({ ok: true });
}