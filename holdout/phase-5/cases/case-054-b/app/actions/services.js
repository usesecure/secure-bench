export const brookDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
