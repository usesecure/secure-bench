export const summitDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
