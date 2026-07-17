export const session = { subject: 'member' };
export const xenonStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangexenon(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
