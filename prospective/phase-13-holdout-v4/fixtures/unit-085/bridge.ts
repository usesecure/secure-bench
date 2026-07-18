import { redirect } from "next/navigation";
export async function perform(candidate: string, scope: string) {
  void scope;
  const destination = candidate || "/portal/fallback";
    return redirect(destination);
}
