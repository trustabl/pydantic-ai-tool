"""Trustabl toolset -- runs the scanner CLI and returns a summary of its findings."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry, ToolFailed, UserError
from pydantic_ai.tools import AgentDepsT
from pydantic_ai.toolsets import FunctionToolset, ToolsetTool
from pydantic_ai.workspaces import (
    SupportsCommands,
    Workspace,
    WorkspaceBackend,
    WorkspaceError,
    WorkspaceReadOnlyError,
    WorkspaceTimeoutError,
    WorkspaceUnavailableError,
    WrapperWorkspace,
)

SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
"""Lowest to highest. Matches the scanner's own `Severity` values."""

_NOT_FOUND_EXIT = 127
_LAUNCH_FAILURE_EXITS = (126, 127)
_ERROR_TAIL_CHARS = 2000

_LAUNCHER = f'command -v "$1" > /dev/null 2>&1 || exit {_NOT_FOUND_EXIT}\nexec env "$@"'
"""Resolve the binary in the workspace, then exec it so the workspace timeout reaches it."""


class TrustablFinding(BaseModel):
    """One production finding from a scan."""

    model_config = ConfigDict(extra='ignore')

    rule_id: str
    severity: str
    title: str
    file_path: str = ''
    start_line: int = 0
    scope: str = ''
    tool_name: str = ''
    explanation: str = ''
    suggested_fix: str = ''


class TrustablInventory(BaseModel):
    """What the scanner found in the repository, before any rule ran.

    Read this before the findings. Counts that look wrong mean the scan was
    pointed somewhere unexpected, and the findings are not worth acting on yet.
    """

    model_config = ConfigDict(extra='ignore')

    agents: int = 0
    tools: int = 0
    subagents: int = 0
    skills: int = 0
    mcp_servers: int = 0
    slash_commands: int = 0
    sdks: list[str] = []


class TrustablScan(BaseModel):
    """A summarised scan. Never the raw report, which reaches megabytes."""

    model_config = ConfigDict(extra='ignore')

    repo: str = ''
    overall_score: float = 0.0
    rules_version: str = ''
    inventory: TrustablInventory
    by_severity: dict[str, int]
    findings: list[TrustablFinding]
    total_findings: int
    excluded_test_findings: int
    below_severity_floor: int
    truncated: bool
    rules_skipped: int = 0


def _is_test(finding: dict[str, Any]) -> bool:
    """Whether the scanner classified this finding's file as a test path."""
    return finding.get('origin') == 'test'


def summarize_scan(
    raw: dict[str, Any],
    *,
    severity_floor: str = 'medium',
    max_findings: int = 50,
) -> TrustablScan:
    """Reduce a raw scan report to something an agent can read.

    Test-path findings are excluded entirely, from the returned findings and
    from `by_severity`, so the histogram can never disagree with the findings
    printed beside it. `excluded_test_findings` reports how many were dropped.

    Args:
        raw: the parsed `trustabl scan --format json` report.
        severity_floor: lowest severity to return. Counts still cover every
            production finding regardless of the floor.
        max_findings: cap on returned findings, highest severity first.
    """
    if severity_floor not in SEVERITY_ORDER:
        raise ValueError(f'severity_floor must be one of {SEVERITY_ORDER}, got {severity_floor!r}')

    all_findings = raw.get('findings') or []
    production = [f for f in all_findings if not _is_test(f)]

    by_severity: dict[str, int] = {}
    for f in production:
        sev = f.get('severity') or 'info'
        by_severity[sev] = by_severity.get(sev, 0) + 1

    floor = SEVERITY_ORDER.index(severity_floor)

    def rank(f: dict[str, Any]) -> int:
        sev = f.get('severity') or 'info'
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0

    above = [f for f in production if rank(f) >= floor]
    above.sort(key=rank, reverse=True)
    returned = above[:max_findings]

    # `sdks` is null rather than [] on a repo with none, so coalesce before iterating.
    sdks = raw.get('sdks') or []
    inventory = TrustablInventory(
        agents=len(raw.get('agents') or []),
        tools=len(raw.get('tools') or []),
        subagents=len(raw.get('subagents') or []),
        skills=len(raw.get('skills') or []),
        mcp_servers=len(raw.get('mcp_servers') or []),
        slash_commands=len(raw.get('slash_commands') or []),
        sdks=[s.get('name', str(s)) if isinstance(s, dict) else str(s) for s in sdks],
    )

    return TrustablScan(
        repo=raw.get('repo') or '',
        overall_score=raw.get('overall_score') or 0.0,
        rules_version=raw.get('rules_version') or '',
        inventory=inventory,
        by_severity=by_severity,
        findings=[TrustablFinding.model_validate(f) for f in returned],
        total_findings=len(production),
        excluded_test_findings=len(all_findings) - len(production),
        below_severity_floor=len(production) - len(above),
        truncated=len(above) > len(returned),
        rules_skipped=len(raw.get('rules_skipped') or []),
    )


def _innermost_backend(workspace: Workspace) -> WorkspaceBackend:
    """The backend under any facades and wrappers."""
    current: WorkspaceBackend = workspace
    while isinstance(current, Workspace):
        current = current.wrapped if isinstance(current, WrapperWorkspace) else current.backend
    return current


def supports_commands(workspace: Workspace) -> bool:
    """Whether `workspace.run` can succeed for this workspace."""
    if not workspace.attached or workspace.read_only:
        return False
    return isinstance(_innermost_backend(workspace), SupportsCommands)


def _raise_tool_failure(error: WorkspaceError) -> None:
    """Report a workspace refusal to the model; a retry cannot fix any of these."""
    if isinstance(error, WorkspaceUnavailableError):
        raise error
    if isinstance(error, WorkspaceReadOnlyError):
        raise ToolFailed('The workspace is read-only; the scan was refused.') from error
    raise ToolFailed(str(error) or f'The workspace operation failed ({type(error).__name__}).') from error


_INSTALL_HINT = (
    'The Trustabl scanner is not available in this workspace.\n'
    'The pinned scanner was downloaded and verified on the host, but this workspace '
    'cannot see that path, which is normal for a sandbox.\n'
    'Install it inside the workspace instead:\n'
    '    brew install trustabl/tap/trustabl\n'
    '    scoop bucket add trustabl https://github.com/trustabl/scoop-trustabl && scoop install trustabl\n'
    'or add the binary to the sandbox image.'
)


class TrustablToolset(FunctionToolset[AgentDepsT]):
    """Exposes one tool that scans the workspace repository and returns a summary.

    The scan runs in the run's workspace, so it sees the repository the agent is
    working in, local or sandboxed. Problems the model cannot fix -- no scanner in
    the workspace, a scan that could not start -- raise `UserError` so the run
    stops with the real cause. A timeout raises `ModelRetry`.
    """

    def __init__(
        self,
        *,
        command: str | None,
        engine_version: str,
        severity_floor: str,
        max_findings: int,
        timeout: float,
    ) -> None:
        super().__init__()
        self._command = command
        self._engine_version = engine_version
        self._severity_floor = severity_floor
        self._max_findings = max_findings
        self._timeout = timeout
        self.add_function(self.scan_repository, name='scan_repository')

    async def get_tools(self, ctx: RunContext[AgentDepsT]) -> dict[str, ToolsetTool[AgentDepsT]]:
        """Offer the tool only when the workspace can run commands."""
        if not supports_commands(ctx.workspace):
            return {}
        return await super().get_tools(ctx)

    async def _resolve_command(self, ctx: RunContext[AgentDepsT]) -> str:
        """Find a scanner the workspace can actually execute.

        Prefers one already on the workspace's PATH. Falls back to the pinned
        release, downloaded and checksum-verified on the host, but only after
        confirming the workspace can see that path -- a host download is
        invisible to a sandbox.
        """
        if self._command is not None:
            return self._command

        probe = await ctx.workspace.run(['sh', '-c', 'command -v trustabl'], timeout=30)
        if probe.exit_code == 0 and probe.stdout.strip():
            return 'trustabl'

        from pydantic_ai_trustabl._binary import ensure_binary

        path = str(ensure_binary(self._engine_version))
        visible = await ctx.workspace.run(['sh', '-c', 'test -x "$1"', 'sh', path], timeout=30)
        if visible.exit_code != 0:
            raise UserError(_INSTALL_HINT)
        return path

    async def scan_repository(self, ctx: RunContext[AgentDepsT], path: str = '.') -> TrustablScan:
        """Scan an agent repository and return its inventory and findings.

        Args:
            ctx: the current agent run context.
            path: directory to scan, relative to the workspace working directory.

        Returns:
            The inventory, a severity histogram over production findings, and the
            findings above the configured severity floor. Read the inventory first:
            counts that look wrong mean the scan was pointed somewhere unexpected.
        """
        command = await self._resolve_command(ctx)
        args = [command, 'scan', path, '--format', 'json', '--no-progress']
        try:
            result = await ctx.workspace.run(['sh', '-c', _LAUNCHER, 'sh', *args], timeout=self._timeout)
        except WorkspaceTimeoutError:
            raise ModelRetry(f'The Trustabl scan timed out after {self._timeout}s.') from None
        except WorkspaceError as e:
            _raise_tool_failure(e)

        output = result.stdout
        tail = f'{result.stdout}\n{result.stderr}'.strip()[-_ERROR_TAIL_CHARS:]

        if result.exit_code == _NOT_FOUND_EXIT and not output.strip():
            raise UserError(_INSTALL_HINT)

        try:
            raw = json.loads(output)
        except ValueError:
            # A non-zero exit with unparsable output is a scanner or setup failure,
            # not something the model can retry its way out of.
            raise UserError(
                f'The Trustabl scan produced no JSON report (exit code {result.exit_code}).'
                f'\n\nScanner output:\n{tail}'
            ) from None

        return summarize_scan(
            raw,
            severity_floor=self._severity_floor,
            max_findings=self._max_findings,
        )
