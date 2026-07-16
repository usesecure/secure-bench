import * as navigation from "next/navigation";

export async function POST(request) {
  const form = await request.formData();
  const destination = String(form.get("next") ?? "/");
  navigation.redirect(destination);
}
