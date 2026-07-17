export const pebbleDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
