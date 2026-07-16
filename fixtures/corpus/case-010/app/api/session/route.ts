import * as navigation from "next/navigation";

const allowedDestinations = new Set(["/dashboard", "/settings"]);

export async function POST(request: Request) {
  const form = await request.formData();
  const candidate = String(form.get("next") ?? "/");
  const destination = allowedDestinations.has(candidate) ? candidate : "/";
  navigation.redirect(destination);
}
