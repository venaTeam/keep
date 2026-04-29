import { NextRequest, NextResponse } from "next/server";
import { activeUsers } from "@/metrics/metrics";

const userHeartbeats = new Map<string, number>();

const HEARTBEAT_TIMEOUT_MS = 60_000;
const CLEANUP_INTERVAL_MS = 30_000;

let cleanupStarted = false;

function startCleanup() {
  if (cleanupStarted) return;
  cleanupStarted = true;
  setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [userId, lastSeen] of userHeartbeats) {
      if (now - lastSeen > HEARTBEAT_TIMEOUT_MS) {
        userHeartbeats.delete(userId);
        removed++;
      }
    }
    if (removed > 0) {
      activeUsers.dec(removed);
      console.log(`[metrics] heartbeat cleanup removed ${removed} inactive users`);
    }
  }, CLEANUP_INTERVAL_MS);
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { userId } = body as { userId?: string };

  if (!userId) {
    return NextResponse.json({ error: "Missing userId" }, { status: 400 });
  }

  const isNew = !userHeartbeats.has(userId);
  userHeartbeats.set(userId, Date.now());

  if (isNew) {
    activeUsers.inc();
    console.log(`[metrics] heartbeat: new user registered, now ${userHeartbeats.size} active`);
  }

  startCleanup();

  return NextResponse.json({ ok: true, activeUsers: userHeartbeats.size });
}