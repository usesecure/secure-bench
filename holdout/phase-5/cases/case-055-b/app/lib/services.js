export const session = { subject: 'member' };
export const cloverStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangeclover(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
