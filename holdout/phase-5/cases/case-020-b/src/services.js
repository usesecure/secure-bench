export const session = { subject: 'member' };
export const thicketStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangethicket(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
