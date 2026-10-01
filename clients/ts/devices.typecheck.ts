import { client } from "./index";
import type { operations } from "./schema";

export async function addDevice(origin: string, session: string, credential: Record<string, unknown>) {
  const api = client(origin, session);
  const start = await api.POST("/v1/passkey_add", { body: { step: "begin" } });
  if (start.data?.step !== "challenge") throw new Error("challenge required");
  const request: operations["passkey_add"]["requestBody"]["content"]["application/json"] = {
    step: "finish", ceremony: start.data.ceremony, credential,
  };
  const finish = await api.POST("/v1/passkey_add", { body: request });
  if (finish.data?.step !== "registered") throw new Error("registration required");
  const registered: number[] = finish.data.credential;
  return { user: finish.data.user, credential: registered };
}

export const finishLogin = (origin: string, ceremony: string, credential: Record<string, unknown>) =>
  client(origin).POST("/v1/login_finish", { body: { ceremony, credential } });
export const finishRegistration = (origin: string, ceremony: string, credential: Record<string, unknown>) =>
  client(origin).POST("/v1/register_finish", { body: { ceremony, credential } });
