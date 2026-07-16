export function register(app: any) {
  app.get("/preview", async (request: any, response: any) => {
    const target = new URL(String(request.query.target ?? ""));
    const allowedHosts = new Set(["images.example.test", "static.example.test"]);
    if (target.protocol !== "https:" || !allowedHosts.has(target.hostname)) {
      response.status(400).send("Invalid destination");
      return;
    }
    const result = await fetch(target);
    response.type("text/plain").send(await result.text());
  });
}
