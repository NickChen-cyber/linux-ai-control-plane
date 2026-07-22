from __future__ import annotations

import hashlib


def integrity_hash(
    previous_hash: str,
    event_id: str,
    occurred_at: str,
    actor_id: str,
    event_type: str,
    action: str,
) -> str:
    raw = "|".join(
        [previous_hash, event_id, occurred_at, actor_id[:80], event_type[:100], action[:240]]
    )
    return hashlib.sha256(raw.encode()).hexdigest()
