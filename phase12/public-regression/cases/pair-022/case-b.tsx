import { redirect } from "next/navigation";
export async function handleb022(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-022">{String(candidate)}</span>; void view;
  return consumeb022(candidate);
}

async function consumeb022(candidate) {
  if (!candidate.startsWith("/")) { return; }
  return redirect(candidate);
}
