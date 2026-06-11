import { createFileRoute } from "@tanstack/react-router";
import { makeEntityRoute } from "@/components/entity-management";

export const Route = createFileRoute("/email-scams")({
  head: () => ({ meta: [{ title: "Email Scams — Scam Detector AI" }] }),
  ...makeEntityRoute("email_scams"),
});
