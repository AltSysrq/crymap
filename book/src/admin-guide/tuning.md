# Tuning

Crymap's tuning options are very limited; in fact, Crymap itself directly
provides only one.

## Thread Count

When certain operations across multiple items, such as fetches or searching,
take too long, Crymap will spin up extra threads to parallelise the work and
reduce latency. By default, it will create up to as many threads as there are
CPU cores.

The environment variable `CRYMAP_MAX_THREADS` can be set to any integer to
override this. Setting it to `1` will completely prevent Crymap from trying to
parallelise work.

Note that you cannot make Crymap fully single-threaded for this operation. Even
if it is set to `1`, Crymap will still spawn extra threads for background
cleanups and idling, which are sufficient to cause the memory allocator to
switch to multi-threaded mode on multi-core systems.

## Memory Allocator

Crymap uses the host system's `malloc()`, so exactly how it gets tuned depends
on your system. Often, you can refer to `malloc(3)` for information on how to
configure the allocator.

Crymap is very conservative about allocating memory and ensures that memory not
needed is freed expediently. The memory allocator itself may not be. In
particular, glibc's `malloc()` (used on most Linux installations) and jemalloc
(used on FreeBSD) will switch to a strategy optimised for multi-core
performance when running on a multi-core system. This can cause Crymap to use
dramatically more memory than it actually needs, potentially by a factor of as
much as 10. If running Crymap on a multi-core system with memory constraints,
it is useful to disable the multi-core allocation strategies.

With glibc `malloc()`, this can be done by setting the environment variable
`M_ARENA_MAX` to `1`.

With jemalloc, a similar thing can be done by setting `MALLOC_CONF` to
`narenas:1`.
