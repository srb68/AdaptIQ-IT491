from dataclasses import dataclass
from math import ceil
from threading import Lock
from time import monotonic


@dataclass
class Bucket:
    tokens: float
    updated_at: float


class TokenBucketLimiter:
    def __init__(self, capacity: int, refill_per_second: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.buckets: dict[str, Bucket] = {}
        self.lock = Lock()

    def consume(self, key: str) -> int | None:
        """Spend one token or return the seconds until one is available."""
        with self.lock:
            now = monotonic()
            bucket = self.buckets.get(key)
            if bucket is None:
                bucket = self.buckets[key] = Bucket(self.capacity, now)

            elapsed = now - bucket.updated_at
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_per_second)
            bucket.updated_at = now

            if bucket.tokens < 1:
                return ceil((1 - bucket.tokens) / self.refill_per_second)

            bucket.tokens -= 1
            return None
