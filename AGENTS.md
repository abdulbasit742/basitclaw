# AGENTS.md

## Scope

These instructions apply to the entire `abdulbasit742/basitclaw` repository. This repository is currently a bootstrap/empty project, so do not assume a language, framework, package manager, deployment target, or architecture.

## Bootstrap workflow

1. Confirm the requested product, users, runtime, deployment target, and non-functional constraints before choosing a stack.
2. Add a concise README.md that explains the project purpose, local setup, configuration, and verification commands.
3. Prefer the smallest maintainable architecture. Do not add frameworks, services, databases, or production dependencies without a concrete need.
4. Commit the selected dependency manifest and lockfile together. Add a practical .gitignore and sanitized environment example when needed.
5. Establish at least one automated smoke test plus lint/format checks before substantial feature work.
6. Keep generated files, build outputs, dependency directories, credentials, private data, and populated environment files out of Git.

## Safety and side effects

- Never commit secrets, tokens, passwords, private keys, or production data.
- Do not deploy, create paid resources, send messages, modify accounts, or perform destructive operations unless the task explicitly authorizes the exact side effect.
- Validate untrusted input at trust boundaries and default to local fixtures or mocks for external systems.
- Preserve unrelated user changes and make focused, reviewable commits.

## Completion checklist

- README and setup instructions match the implemented project.
- The documented install, test, lint, and build commands were actually run where available.
- No secrets, generated artifacts, or unrelated changes were introduced.
- The final handoff summarizes changed files, verification evidence, risks, and next steps.
