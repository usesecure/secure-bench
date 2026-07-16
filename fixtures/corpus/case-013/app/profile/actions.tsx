"use server";

import { database } from "@/server/database";

export async function updateProfile(formData: FormData) {
  const recordId = String(formData.get("recordId") ?? "");
  const displayName = String(formData.get("displayName") ?? "");
  return database.profile.update({ where: { id: recordId }, data: { displayName } });
}
