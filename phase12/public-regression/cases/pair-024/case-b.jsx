import { redirect } from "next/navigation";
export async function handleb024(request) {
  const candidate = request.query.value;
  const view = <span data-case="pair-024">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!forwarded.startsWith("/")) { return; }
  return redirect(forwarded);
}
