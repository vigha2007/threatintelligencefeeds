import { c as createServerRpc } from "./createServerRpc-B6dqUJkk.mjs";
import { c as createServerFn } from "./server-DkvSOJyR.mjs";
import { a as allEntityKeys, e as entities } from "./threat-entities-SRQqKOBI.mjs";
import "../_libs/seroval.mjs";
import "../_libs/react.mjs";
import { e as enumType, o as objectType, n as numberType, r as recordType, s as stringType, u as unknownType, a as unionType } from "../_libs/zod.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "node:stream";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "../_libs/tanstack__react-router.mjs";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";
const entityKeySchema = enumType(allEntityKeys);
const listEntity_createServerFn_handler = createServerRpc({
  id: "9370c38e835314b97d0feefd9b68122b929bfc6e659002fa67a94e09ae0508c9",
  name: "listEntity",
  filename: "src/lib/entities.functions.ts"
}, (opts) => listEntity.__executeServer(opts));
const listEntity = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  entity: entityKeySchema,
  limit: numberType().int().positive().optional(),
  offset: numberType().int().min(0).optional()
}).parse(d)).handler(listEntity_createServerFn_handler, async ({
  data
}) => {
  const limit = data.limit ?? 200;
  const offset = data.offset ?? 0;
  const res = await fetch(`${JAVA_BASE}/api/v1/entity/${data.entity}?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error("Failed to fetch from Java backend");
  const json = await res.json();
  return {
    rows: json.rows ?? [],
    total: json.total ?? 0,
    limit,
    offset
  };
});
const createEntity_createServerFn_handler = createServerRpc({
  id: "7740c0594d9af779be21bf8d7bbe6fe08352c64d801d9506b230ab57cda96398",
  name: "createEntity",
  filename: "src/lib/entities.functions.ts"
}, (opts) => createEntity.__executeServer(opts));
const createEntity = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  entity: entityKeySchema,
  values: recordType(stringType(), unknownType())
}).parse(d)).handler(createEntity_createServerFn_handler, async ({
  data
}) => {
  const def = entities[data.entity];
  const parsed = def.schema.parse(data.values);
  const res = await fetch(`${JAVA_BASE}/api/v1/entity/${data.entity}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(parsed)
  });
  if (!res.ok) throw new Error("Failed to insert entity in Java backend");
  const json = await res.json();
  return {
    row: json.row
  };
});
const deleteEntity_createServerFn_handler = createServerRpc({
  id: "aeca7cbdb3f92f362d3fab6b7c0347b050e2873d52b97029bae376ca4a1d1b83",
  name: "deleteEntity",
  filename: "src/lib/entities.functions.ts"
}, (opts) => deleteEntity.__executeServer(opts));
const deleteEntity = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  entity: entityKeySchema,
  id: unionType([stringType(), numberType()]).transform(String)
}).parse(d)).handler(deleteEntity_createServerFn_handler, async ({
  data
}) => {
  const res = await fetch(`${JAVA_BASE}/api/v1/entity/${data.entity}/${data.id}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error("Failed to delete entity");
  return {
    ok: true
  };
});
export {
  createEntity_createServerFn_handler,
  deleteEntity_createServerFn_handler,
  listEntity_createServerFn_handler
};
