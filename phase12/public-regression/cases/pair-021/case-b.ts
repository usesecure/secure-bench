import { redirect } from "next/navigation";
export async function handleb021(request) {
  const candidate = request.body.value;
  if (!candidate.startsWith("/")) { return; }
  return redirect(candidate);
}
