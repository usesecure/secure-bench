import { redirect } from "next/navigation";
export async function consumeb023(candidate) {
  if (!candidate.startsWith("/")) { return; }
  return redirect(candidate);
}
