"""Trustabl scanning capability."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import UserError
from pydantic_ai.tools import AgentDepsT, RunContext

from pydantic_ai_trustabl._toolset import SEVERITY_ORDER, TrustablToolset

_SCAN_INSTRUCTIONS = (
    'You can scan an agent repository for reliability and safety weaknesses with the '
    '`scan_repository` tool. Read the returned inventory before the findings: if the agent, '
    'tool and skill counts look wrong, the scan was pointed at the wrong directory and the '
    'findings are not worth acting on yet. An empty result is not a pass either, because a '
    'repository with no recognised agent surfaces produces no findings. Treat each finding as '
    'a claim to verify: open the file and read enough surrounding code to confirm it before '
    'changing anything, then fix confirmed issues one at a time.'
)

_ENGINE_VERSION = '0.1.13'


@dataclass
class Trustabl(AbstractCapability[AgentDepsT]):
    """Scans the workspace repository with Trustabl and hands the findings to the agent.

    Adds a `scan_repository` tool that runs the Trustabl scanner in the run's
    workspace and returns a summary: the inventory, a severity histogram over
    production findings, and the findings above `severity_floor`. The agent
    validates and fixes them with its own tools; this capability edits nothing.

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
    ```

    The scanner is resolved from the workspace's PATH when present; otherwise the
    pinned release is downloaded and verified against the release's
    `checksums.txt` before anything is executed.
    """

    command: str | None = None
    """Name or path of the scanner binary. `None` resolves it automatically."""

    engine_version: str = _ENGINE_VERSION
    """Scanner release to download when none is on the workspace's PATH.

    Pinned rather than tracking latest, so checksum verification stays meaningful
    and a bad scanner release cannot reach every user at once."""

    severity_floor: str = 'medium'
    """Lowest severity to return. Counts still cover every production finding."""

    max_findings: int = 50
    """Cap on returned findings. A full report reaches megabytes, which is why
    this tool summarises rather than returning the raw scan."""

    timeout: float = 600.0
    """Maximum seconds for one scan."""

    guidance: str | None = None
    """Replaces the default verify-then-fix instructions. `''` contributes none."""

    def __post_init__(self) -> None:
        if self.severity_floor not in SEVERITY_ORDER:
            raise UserError(
                f'severity_floor must be one of {SEVERITY_ORDER}, got {self.severity_floor!r}'
            )
        if self.max_findings < 1:
            raise UserError(f'max_findings must be at least 1, got {self.max_findings}')

    async def before_run(self, ctx: RunContext[AgentDepsT]) -> None:
        """Fail at the start of a run that has no workspace to scan."""
        if not ctx.workspace.attached:
            raise UserError(
                'Trustabl needs a workspace to scan. Add one to the agent, for example '
                "`LocalWorkspace('.')`."
            )

    def get_toolset(self) -> TrustablToolset[AgentDepsT]:
        """Build the toolset providing `scan_repository`."""
        return TrustablToolset[AgentDepsT](
            command=self.command,
            engine_version=self.engine_version,
            severity_floor=self.severity_floor,
            max_findings=self.max_findings,
            timeout=self.timeout,
        )

    def get_instructions(self) -> str | None:
        """Verify-then-fix guidance, unless `guidance` overrides it."""
        if self.guidance is not None:
            return self.guidance or None
        return _SCAN_INSTRUCTIONS

    @classmethod
    def get_serialization_name(cls) -> str:
        """Name this capability answers to in an agent spec."""
        return 'Trustabl'
