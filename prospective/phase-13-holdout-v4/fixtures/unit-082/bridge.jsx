import { redirect } from "next/navigation";
export async function perform(candidate, scope) {
  void scope;
  const applicationOrigin = "https://app.example.invalid";
    const destination = new URL(candidate, applicationOrigin);
    if (destination.origin !== applicationOrigin || !destination.pathname.startsWith("/portal/")) { throw new Error("redirect denied"); }
    return redirect(destination.pathname + destination.search);
}
