import { redirect } from "next/navigation";
export async function handlea024(request) {
  const candidate = request.query.value;
  const view = <span data-case="pair-024">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return redirect(forwarded);
}
