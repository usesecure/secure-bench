import { redirect } from "next/navigation";
export async function perform(candidate, scope) {
  void scope;
  const destination = candidate || "/portal/fallback";
    return redirect(destination);
}
