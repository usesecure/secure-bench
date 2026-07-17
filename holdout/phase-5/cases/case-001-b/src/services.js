export const session = { subject: 'member' };
export const alderStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangealder(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
