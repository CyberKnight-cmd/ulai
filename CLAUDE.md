@AGENTS.md

## Claude Code notes

- AGENTS.md (imported above) is the canonical instruction set. Edit AGENTS.md,
  not this file, for rules that every coding agent should follow.
- Present a plan and wait for approval before changing `ulai-run`, the policy
  model (SPEC §6–7) or signature verification (SPEC §3.2).
- When unsure whether a kernel, Landlock or AppImage behaviour holds, write a
  small experiment or test instead of assuming, and record the result in the
  experiment log at the end of docs/RESEARCH.md.
