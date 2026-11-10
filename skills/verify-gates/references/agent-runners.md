# Running the review pass with Claude Code and Codex

## Contents

- Same context for every reviewer
- One packet, start to finish
- What the sandbox gives the reviewer
- What the audit refuses
- Session-log formats the audit assumes
- Which model reviews what
- Before a pilot

## Same context for every reviewer

Both CLIs are run the same way (headless in a batch with `run_reviews.py`, or interactively for one packet), on the same exported folder:

- the same instructions: `AGENTS.md` in the folder. Codex reads it directly; `CLAUDE.md` holds only `@AGENTS.md`, so Claude Code reads the identical text;
- the same single prompt (`PROMPT.txt`);
- an empty config home, so neither CLI loads user-level instructions, memory, plugins, MCP servers, skills or earlier sessions.

Nothing in the repo is mounted, so the analyst's reports, the dataset, the evals, the samples and the other packets are not reachable at all. The session-log audit is a second line of defence.

## One packet, start to finish

1. Export the packet's review folder. This happens automatically on the first launch, or you can run it yourself:

   ```
   .venv/bin/python tools/verify/packet.py --export <packet_id>
   ```

   It lands in `$XDG_RUNTIME_DIR/tripwire-review/review-<packet_id>/`, outside the repo.

2. Launch one CLI:

   ```
   .venv/bin/python tools/verify/review_shell.py <packet_id> --cli claude --run
   ```

   Use `--cli codex` for the other CLI. Without `--run`, the tool only prints the bwrap command. Each CLI works on its own copy of the folder (`review-<packet_id>.<cli>/review`), so neither sees the other's verdicts.

3. Paste the prompt the tool prints, which is `PROMPT.txt`. Send nothing else: no follow-up, no hint, no correction, no slash command other than `/exit`. Approve nothing outside the folder. The settings make prompts unnecessary.

4. When `verdicts.json` is written, exit the CLI.

5. Record the verdicts:

   ```
   .venv/bin/python tools/verify/record_verdict.py --packet <packet_id> --session-log auto --cli <cli>
   ```

   The verdicts and the session log are found in the run folder. The model id is read from the log; a `--by` that differs from it is refused.

If a session went wrong (an extra message, a crash), start it again with `review_shell.py ... --fresh`. That discards the unrecorded session. A recorded run is never edited; a second look is a new run.

## Headless and batch runs

- `review_shell.py <packet_id> --cli claude --print --run` runs `claude -p` on the launch prompt and exits by itself. `--cli codex --print --run` runs `codex exec` the same way (not yet run end to end; see below). `--model <id>` pins the model for the whole session. The sandbox's empty config ignores the user's own model setting, so without it the CLI default is used.
- `tools/verify/run_reviews.py --cli <cli> --model <id> [--jobs 4] [--timeout 3600] [--only ...]` runs every packet this CLI has not reviewed yet, 4 at a time, and records each one as soon as it finishes (one recorder at a time; `record_verdict.py` marks the queue per CLI under a lock). Keep parallelism near 4: each sandbox copies the same login, and a token refresh in several at once can fail. Once a review is recorded, its run folder moves to `--archive` (default `~/.cache/tripwire-review-archive/`, on disk), and the packet's export is dropped (it is rebuilt on the next launch). `$XDG_RUNTIME_DIR` is a small tmpfs that fills after a few hundred folders, and the run folder holds the only copy of the session log whose hash the sidecar records. A single review run by hand with `review_shell.py` stays where it is.
- A reviewer that the CLI's cyber safeguard stops either writes nothing or is moved to a fallback model partway (`model_refusal_fallback` in the log). The audit then refuses the log for naming two models. Seen on obfuscated droppers and worm bundles with both Opus 5.5 and Sonnet 5.5. Pinning a model does not prevent it. Those packets need the other CLI.
- Claude Code (v2.1.x) warns that `Write(...)` allow and deny rules are not matched by file permission checks (only `Edit(...)` rules are). `packet.CLAUDE_SETTINGS` carries both, so the `Edit(...)` rules enforce the limit; the folder being the only thing mounted holds it anyway.
- Codex headless logs from v0.160.0 and v0.163.0 have regression fixtures. The v0.163.0 pilot used `gpt-6.1-sol` in the review sandbox. Check `codex exec --help` and audit the first packet when upgrading the CLI. Newer logs record the prompt as a completed `UserMessage` item and a tagged user response message; the audit cross-checks these representations. Fix format changes in the reader, never in a reviewer's log.

## What the sandbox gives the reviewer

`review_shell.py` starts the CLI under `bwrap` with:
- the network namespace kept, because both CLIs need their API;
- the review copy, read-write, at `/review` (the working directory);
- the config home at `/home/reviewer` (`CLAUDE_CONFIG_DIR` or `CODEX_HOME` points inside it);
- the CLI's own install, read-only;
- the system directories, read-only;
- a private `/tmp`.

**Login.** The login file (`~/.claude/.credentials.json` or `~/.codex/auth.json`) is copied in for the session and deleted when the session ends. An API key in the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) is passed through instead when there is no login file. If the CLI refreshes its token inside the sandbox, the host login may need `login` again afterwards.

**Settings per CLI.**
- Claude Code: `settings.json` denies `Bash`, `Agent`/`Task`, `WebFetch`, `WebSearch` and reads under `~`, and allows reads in `/review` and writing `verdicts.json`. The reviewer uses Read, Grep and Glob.
- Codex: started with `--sandbox workspace-write --ask-for-approval never`, with network off for the commands it runs. It reads with shell commands.

The two tool surfaces differ, but the folder, instructions, prompt and code are the same.

## What the audit refuses

`record_verdict.py` fails closed. A run is refused when:
- the log is not one of the formats below;
- any line is not JSON;
- the log shows no tool action;
- the log holds more than one session or more than one model;
- the operator sent anything but the launch prompt, unchanged, or ran a slash command other than `/exit`;
- the session's working directory is not `/review`;
- an action names a path outside `/review` (`..`, `~`, `$HOME`, absolute paths, `cd` elsewhere, recursive searches from `/`), apart from system binaries, `/dev/null` and `/tmp`;
- the reviewer used a tool outside the allowed set: web, agents, MCP tools, image tools;
- a command names reports, the dataset, evals, samples, analysis scratch, the packet index or another packet.

Tool output and search patterns are not audited as reads. Absolute paths in commands are refused even inside a search pattern, which is why the reviewer instructions ask for relative paths. Plain-text transcripts are no longer accepted for agent runs.

## Session-log formats the audit assumes

These assumptions were written before a real pilot. Check them against the first real logs of each CLI and add those logs, cleaned, as test fixtures.

**Claude Code** writes `<CLAUDE_CONFIG_DIR>/projects/<cwd slug>/<session id>.jsonl`. Subagent sidechains are `.jsonl` files below it; all files under `projects/` are audited. Each line is an object with:
- `type`: `user`, `assistant`, `summary`, `system`, `file-history-snapshot` or `queue-operation`;
- `cwd`, `sessionId`, `isSidechain`, `isMeta` and `message`.

Confirmed against a real v2.1.x log (packet pilot): the same sessions also interleave per-turn bookkeeping lines the audit reads nothing from and must not refuse: `mode`, `permission-mode`, `atis-latch`, `last-prompt`, `ai-title`, `attachment` (an environment snapshot, not a tool call or operator message) and `file-history-delta` (a file-backup record, the one such line with no `sessionId`). Operator messages and tool calls still ride only on `user`/`assistant` lines, so these are listed as known-and-ignored while any genuinely unseen type is still refused.

What the audit reads from it:
- **Tool calls:** assistant content blocks `{"type": "tool_use", "name", "input"}`.
- **Model:** `message.model`.
- **Operator messages:** user lines that are not meta, sidechain or tool results.
- **Slash commands:** appear as `<command-name>/x</command-name>`.

**Codex** writes `<CODEX_HOME>/sessions/YYYY/MM/DD/rollout-*.jsonl`. Each line is `{"type", "payload"}` with type `session_meta` (holds `cwd`), `turn_context` (holds `cwd` and `model`), `response_item`, `event_msg`, `compacted`, `world_state` or `token_usage_record`. Model changes in `world_state` count toward the single-model check; token usage is bookkeeping.

What the audit reads from it:
- **Tool calls:** `response_item` payloads of type `function_call` (`shell`, `exec_command` and the like, whose `arguments` is a JSON string holding `command` as argv or `cmd`), `local_shell_call` or `custom_tool_call` `apply_patch`. A custom `exec` wrapper is parsed statically: only literal arguments, constant bindings and direct allowed tool calls are accepted. The extracted calls undergo the same path and tool checks. Dynamic wrappers and unknown tools are refused.
- **Typed prompts:** legacy `event_msg` `user_message`, completed `UserMessage` items, or user response messages. Duplicate representations must agree. Injected `AGENTS.md` and environment context tagged with their known content kinds are excluded; ordinary user messages are counted.

## Which model reviews what

The records are labelled by a Claude model, so a Claude reviewer shares the analyst's family and may accept the same plausible readings. Codex (a GPT model) is therefore the primary independent reviewer, and Claude is the second.

Agreement between reviewer models is reported per layer on the claims both judged (`dataset/tables/kappa.csv`). It measures where labels are harder, not accuracy: no human reference exists.

## Before a pilot

- Confirm that sending defanged code slices to each provider is allowed under its terms, and note it for the paper's ethics section.
- Check the flags and config keys against the installed versions: `claude --help`, `codex --help`, and the Codex config reference for `approval_policy`, `sandbox_mode`, `sandbox_workspace_write.network_access`, `tools.web_search` and `projects.<path>.trust_level`. They change between releases.
- Run `review_shell.py <packet_id> --cli <cli>` without `--run` and read the printed command once.
