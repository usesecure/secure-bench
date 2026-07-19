function syntheticExecute(untrustedInput) {
  return eval(untrustedInput);
}

syntheticExecute("1 + 1");
