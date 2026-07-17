export const keystoneDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
