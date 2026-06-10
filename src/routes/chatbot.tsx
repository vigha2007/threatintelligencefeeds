import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/chatbot")({
  beforeLoad: () => {
    throw redirect({ to: "/chatbot" as never });
  },
  component: () => null,
});
