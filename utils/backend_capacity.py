"""Fail-fast admission control for MongoDB work executed by gevent workers."""

import os

from gevent import joinall, spawn
from gevent.lock import BoundedSemaphore


MONGO_MAX_POOL_SIZE = max(1, int(os.getenv("MONGO_MAX_POOL_SIZE", "20")))
REQUESTED_BACKEND_CONCURRENCY = max(
    1,
    int(os.getenv("MAX_GREENLETS", str(MONGO_MAX_POOL_SIZE))),
)
MAX_BACKEND_CONCURRENCY = min(
    MONGO_MAX_POOL_SIZE,
    REQUESTED_BACKEND_CONCURRENCY,
)
BACKEND_TIMEOUT = max(0.1, float(os.getenv("GREENLET_TIMEOUT", "10")))


class BackendBusyError(RuntimeError):
    """Signal that no database capacity is available for new work."""


class BackendTimeoutError(TimeoutError):
    """Signal that admitted database work exceeded the request deadline."""


class BackendCapacity:
    """Reserve bounded database slots before starting cooperative tasks."""

    def __init__(self, max_concurrency):
        """Create an admission controller with at least one backend slot."""
        self.max_concurrency = max(1, int(max_concurrency))
        self._slots = BoundedSemaphore(self.max_concurrency)

    def _reserve(self, count):
        """Reserve every requested slot atomically from the caller's view."""
        reserved = 0
        for _index in range(count):
            if not self._slots.acquire(blocking=False):
                for _reserved_index in range(reserved):
                    self._slots.release()
                raise BackendBusyError("Database concurrency limit reached")
            reserved += 1

    def _run_reserved_tasks(self, indexed_tasks, results):
        """Run one sequential task lane and release its reserved slot."""
        try:
            for index, task in indexed_tasks:
                results[index] = task()
        finally:
            self._slots.release()

    def run_tasks(self, tasks, timeout=BACKEND_TIMEOUT):
        """Run callables with bounded parallelism or fail before spawning any."""
        tasks = list(tasks)
        if not tasks:
            return []

        worker_count = min(len(tasks), self.max_concurrency)
        self._reserve(worker_count)
        task_lanes = [[] for _index in range(worker_count)]
        results = [None] * len(tasks)
        for index, task in enumerate(tasks):
            task_lanes[index % worker_count].append((index, task))

        greenlets = []
        unassigned_slots = worker_count
        try:
            for task_lane in task_lanes:
                greenlets.append(
                    spawn(self._run_reserved_tasks, task_lane, results)
                )
                unassigned_slots -= 1
        except Exception:
            # Slots already assigned to greenlets are released by their
            # wrappers; only reservations without a greenlet are returned here.
            for _index in range(unassigned_slots):
                self._slots.release()
            for greenlet in greenlets:
                greenlet.kill(block=False)
            raise

        joinall(greenlets, timeout=timeout)
        unfinished = [greenlet for greenlet in greenlets if not greenlet.ready()]
        if unfinished:
            for greenlet in unfinished:
                greenlet.kill(block=False)
            raise BackendTimeoutError("Database work exceeded its deadline")

        for greenlet in greenlets:
            if greenlet.exception is not None:
                raise greenlet.exception
        return results


BACKEND_CAPACITY = BackendCapacity(MAX_BACKEND_CONCURRENCY)


def run_backend_tasks(tasks, timeout=BACKEND_TIMEOUT):
    """Run database callables through the shared per-worker capacity limit."""
    return BACKEND_CAPACITY.run_tasks(tasks, timeout=timeout)
