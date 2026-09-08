import { parentPort, workerData } from 'node:worker_threads';
import { createSqliteState } from '../src/sqlite.js';
const state = createSqliteState({ path: workerData.path, maxReceipts: 100, maxCredentials: 100, busyTimeoutMs: 10000 });
parentPort.postMessage({ ready: true });
parentPort.once('message', async () => {
  try {
    const value = await state.receipts.issueOnce(workerData.input, () => ({ producer: workerData.serial }));
    parentPort.postMessage({ value });
  } catch (error) { parentPort.postMessage({ error: error.message }); }
  finally { state.close(); }
});
