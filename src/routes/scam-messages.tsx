import { createFileRoute } from "@tanstack/react-router";
import { makeEntityRoute } from "@/components/entity-management";

export const Route = createFileRoute("/scam-messages")({
  head: () => ({ meta: [{ title: "Scam Messages — Scam Detector AI" }] }),
  ...makeEntityRoute("scam_messages"),
});
