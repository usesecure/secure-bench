import { redirect } from "next/navigation";
export async function handlea022(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-022">{String(candidate)}</span>; void view;
  return consumea022(candidate);
}

async function consumea022(candidate) {
  return redirect(candidate);
}
