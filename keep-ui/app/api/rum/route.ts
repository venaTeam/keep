
import { getConfig } from "@/shared/lib/server/getConfig";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const data = await request.json();
  const config = getConfig();
  
  // Construct the backend URL
  const apiUrl = config.API_URL || "http://keep-backend:8080";
  const backendUrl = `${apiUrl}/rum`;

  try {
    await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });
  } catch (e) {
    // Fail silently
    console.error("Failed to report RUM metrics", e);
  }
  
  return NextResponse.json({ status: "ok" });
}
