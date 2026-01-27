// GithubButton.tsx - Client Component
"use client";

import { Button } from "@tremor/react";
import { RiGithubFill } from "@remixicon/react";

export function GithubButton() {
  return (
    <Button
      icon={RiGithubFill}
      size="lg"
      className="mt-4"
      onClick={() => window.open("https://github.com/keephq/keep", "_blank")}
    >
      Star us on GitHub
    </Button>
  );
}
