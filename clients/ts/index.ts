import createClient from "openapi-fetch";
import type { paths } from "./schema";

export const client = (baseUrl: string, session?: string) => {
  let base: URL;
  try { base = new URL(baseUrl); }
  catch { throw new Error("invalid service origin"); }
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(base.hostname);
  if ((base.protocol !== "https:" && !(base.protocol === "http:" && loopback)) ||
      base.username || base.password || base.search || base.hash || base.pathname !== "/") {
    throw new Error("invalid service origin");
  }
  return createClient<paths>({
    baseUrl: base.origin,
    headers: session ? { Authorization: `Bearer ${session}` } : {},
    fetch: async (request) => {
      const target = new URL(request.url);
      if (target.origin !== base.origin) {
        throw new Error("invalid service origin");
      }
      // Enforce these at the actual fetch boundary, after per-call options and
      // middleware have run. No redirect may replay a sensitive JSON body.
      try {
        return await fetch(new Request(request, {
          redirect: "error", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
        }));
      } catch { throw new Error("service unavailable"); }
    },
  });
};
export type { paths, components, operations } from "./schema";
