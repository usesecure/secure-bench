"use server";

import { currentSession } from "@/server/session";
import { database } from "@/server/database";

export async function updateProfile(formData: FormData) {
  const session = await currentSession();
  if (!session?.user.permissions.includes("profile:write")) {
    throw new Error("Forbidden");
  }
  const recordId = String(formData.get("recordId") ?? "");
  const displayName = String(formData.get("displayName") ?? "");
  return database.profile.update({
    where: { id: recordId, organizationId: session.user.organizationId },
    data: { displayName }
  });
}
