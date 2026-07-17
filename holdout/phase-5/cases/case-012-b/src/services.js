export const session = { subject: 'member' };
export const lagoonStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangelagoon(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
