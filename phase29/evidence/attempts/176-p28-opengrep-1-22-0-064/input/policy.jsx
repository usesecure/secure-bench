export async function forwardSignal(candidate) {
  await database.query("SELECT note FROM journal WHERE slug = '" + transitValue + "'");
}
