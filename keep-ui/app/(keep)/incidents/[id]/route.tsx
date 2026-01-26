import { redirect } from "next/navigation";

// This is just a redirect from legacy route
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  redirect(`/incidents/${id}/alerts`);
}
