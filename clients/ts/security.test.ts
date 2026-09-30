import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { client } from "./index.ts";

test("refuse ambiguous and plaintext remote origins", () => {
  for (const url of ["synthetic-private-marker", "http://remote.example", "https://user:secret@example.test",
    "https://example.test/path", "https://example.test?query", "https://example.test#fragment"]) {
    assert.throws(() => client(url, "synthetic-session"), { message: "invalid service origin" });
  }
});

test("refuse redirects and per-call origin overrides before leaking requests", async () => {
  let received = 0;
  const target = createServer((_request, response) => { received++; response.end("{}"); });
  target.listen(0, "127.0.0.1");
  await once(target, "listening");
  const targetUrl = `http://127.0.0.1:${(target.address() as import("node:net").AddressInfo).port}`;
  const source = createServer((_request, response) => {
    response.writeHead(307, { location: targetUrl + "/v1/register_begin" });
    response.end();
  });
  source.listen(0, "127.0.0.1");
  await once(source, "listening");
  const base = `http://127.0.0.1:${(source.address() as import("node:net").AddressInfo).port}`;
  try {
    const api = client(base, "synthetic-session");
    await assert.rejects(api.POST("/v1/register_begin", {
      body: { bootstrap: "synthetic-bootstrap" }, redirect: "follow",
    }), { message: "service unavailable" });
    await assert.rejects(api.POST("/v1/register_begin", {
      body: { bootstrap: "synthetic-bootstrap" }, baseUrl: targetUrl,
    }));
    assert.equal(received, 0);
  } finally {
    source.closeAllConnections(); target.closeAllConnections();
    await Promise.all([new Promise<void>(r => source.close(() => r())), new Promise<void>(r => target.close(() => r()))]);
  }
});

test("enforce privacy options after caller overrides", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (request) => {
    assert.ok(request instanceof Request);
    assert.equal(request.cache, "no-store");
    assert.equal(request.credentials, "omit");
    assert.equal(request.redirect, "error");
    assert.equal(request.referrerPolicy, "no-referrer");
    return new Response("{}", { headers: { "content-type": "application/json" } });
  };
  try {
    await client("https://example.test").POST("/v1/register_begin", {
      body: {}, credentials: "include", cache: "force-cache", redirect: "follow", referrerPolicy: "unsafe-url",
    });
  } finally { globalThis.fetch = original; }
});
