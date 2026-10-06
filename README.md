# pydantic-ai-trustabl

Scan an agent repository for reliability and safety weaknesses from inside a
Pydantic AI agent, and hand the findings back for the agent to fix.

```bash
pip install pydantic-ai-trustabl
```

## The problem

[Trustabl](https://github.com/trustabl/agent-reliability-analyzer) analyses agent
code: unsafe tool grants, missing turn limits, untyped tools, prompt-injectable
shell tools, fetch calls with no timeout. It ships as a CLI and as editor
plugins. There was no way to give a Pydantic AI agent the same scan-and-fix loop
from your own code.

## The solution

`Trustabl` adds a `scan_repository` tool that runs the scanner in the run's
workspace, summarises the report, and returns it. The agent then verifies each
finding and fixes the real ones with whatever tools it already has.

```python
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_trustabl import Trustabl

agent = Agent(
    'anthropic:claude-sonnet-5',
    capabilities=[
        LocalWorkspace('.'),
        Trustabl(),
    ],
)

result = agent.run_sync('Scan this repository and fix the confirmed findings.')
print(result.output)
```

## Why it summarises

A full scan of a large agent repository reaches several megabytes, far past what
is useful in a tool result. The tool returns the inventory, a severity histogram,
and the findings above a floor, with `truncated` set when any were dropped.

Two details worth knowing:

- **Test-path findings are excluded**, from the returned findings and from the
  histogram. The scanner classifies them with `origin: test`. Counting them would
  produce a histogram that contradicts the findings printed beside it.
- **`rules_skipped` is reported.** When the rule pack is newer than the scanner,
  rules are skipped silently. A zero finding count with a non-zero
  `rules_skipped` means the scan was incomplete, not that the code is clean.

## Options

| Option | Default | What it does |
|---|---|---|
| `command` | `None` | Binary name or path. `None` resolves it automatically |
| `engine_version` | `0.1.13` | Scanner release to download when none is on PATH |
| `severity_floor` | `medium` | Lowest severity returned. Counts ignore the floor |
| `max_findings` | `50` | Cap on returned findings, worst first |
| `timeout` | `600.0` | Seconds allowed for one scan |
| `guidance` | `None` | Replaces the default instructions. `''` contributes none |

## How the scanner is found

1. If `trustabl` is on the workspace's PATH, that is used.
2. Otherwise the pinned release is downloaded and its SHA-256 checked against
   the release's `checksums.txt`. **Nothing is executed before the checksum
   matches.**
3. A host download is invisible to a sandbox, so the capability confirms the
   workspace can see the binary and otherwise raises with install instructions.

The version is pinned rather than tracking latest, so checksum verification stays
meaningful and a bad scanner release cannot reach every user at once.

## Privacy

The scan runs where your agent runs. There is no hosted scanner, no account, no
code upload, and no model in the analysis path. The only network calls are
fetching the scanner on first use and the versioned rule pack at scan time.

## Links

- [Scanner and rule packs](https://github.com/trustabl/agent-reliability-analyzer)
- [Ecosystem integrations](https://github.com/trustabl/agent-reliability-analyzer/blob/main/docs/integrations.md)
- [Report an issue](https://github.com/trustabl/pydantic-ai-tool/issues)

Apache-2.0
