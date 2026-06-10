import { createFileRoute } from "@tanstack/react-router";
import { makeEntityRoute } from "@/components/entity-management";

export const Route = createFileRoute("/_authenticated/malicious-ips")({
  head: () => ({ meta: [{ title: "Malicious IPs — Scam Detector AI" }] }),
  ...makeEntityRoute("malicious_ips"),
});
