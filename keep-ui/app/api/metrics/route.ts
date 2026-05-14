import { NextRequest, NextResponse } from "next/server";
import { register } from "@/metrics/metrics";

export async function GET(req: NextRequest) {
  const metrics = await register.metrics();

  return new NextResponse(metrics, { 
    status: 200, 
    headers: { 'Content-Type': register.contentType } 
  }
);
}
