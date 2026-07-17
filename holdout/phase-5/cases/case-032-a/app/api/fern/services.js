export const session = { subject: 'member' };
export const fernStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangefern(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
