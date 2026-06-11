import { createFileRoute } from "@tanstack/react-router";
import { makeEntityRoute } from "@/components/entity-management";

export const Route = createFileRoute("/spam-calls")({
  head: () => ({ meta: [{ title: "Spam Calls — Scam Detector AI" }] }),
  ...makeEntityRoute("spam_calls"),
});
