from __future__ import annotations

import asyncio
from typing import Any, Callable


class IncidentRecheckScheduler:
    """Poll due waiting_recheck runs and dispatch sync recheck callbacks."""

    def __init__(
        self,
        analysis_store: Any,
        recheck_callback: Callable[[str], dict[str, Any]],
        *,
        stale_run_callback: Callable[[str], dict[str, Any]] | None = None,
        stale_after_seconds: int = 180,
        poll_interval_seconds: int = 15,
        batch_size: int = 10,
    ) -> None:
        self.analysis_store = analysis_store
        self.recheck_callback = recheck_callback
        self.stale_run_callback = stale_run_callback
        self.stale_after_seconds = max(60, int(stale_after_seconds))
        self.poll_interval_seconds = max(1, int(poll_interval_seconds))
        self.batch_size = max(1, int(batch_size))

    async def run_once(self) -> dict[str, int]:
        stale_count = 0
        recovered_count = 0
        if self.stale_run_callback is not None:
            stale_runs = self.analysis_store.list_stale_running(
                stale_after_seconds=self.stale_after_seconds,
                limit=self.batch_size,
            )
            stale_count = len(stale_runs)
            for run in stale_runs:
                result = await asyncio.to_thread(
                    self.stale_run_callback,
                    run.analysis_id,
                )
                if isinstance(result, dict) and result.get("recovered"):
                    recovered_count += 1

        due_runs = self.analysis_store.list_due_rechecks(
            limit=self.batch_size
        )

        executed = 0
        for run in due_runs:
            result = await asyncio.to_thread(
                self.recheck_callback,
                run.analysis_id,
            )
            if isinstance(result, dict) and result.get("executed"):
                executed += 1

        summary = {
            "due": len(due_runs),
            "executed": executed,
        }
        if self.stale_run_callback is not None:
            summary.update(
                {
                    "stale": stale_count,
                    "recovered": recovered_count,
                }
            )
        return summary

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.run_once()
            except Exception as exc:
                print(f"[incident-recheck] scheduler error: {exc}")

            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self.poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass
