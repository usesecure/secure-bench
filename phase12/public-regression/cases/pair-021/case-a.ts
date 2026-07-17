import { redirect } from "next/navigation";
export async function handlea021(request) {
  const candidate = request.body.value;
  return redirect(candidate);
}
