import { createFileRoute } from "@tanstack/react-router";
import { makeEntityRoute } from "@/components/entity-management";

export const Route = createFileRoute("/phishing-urls")({
  head: () => ({ meta: [{ title: "Phishing URLs — Scam Detector AI" }] }),
  ...makeEntityRoute("phishing_urls"),
});
