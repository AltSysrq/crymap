# Tuning

Crymap's performance tuning options are very limited; in fact, Crymap itself
does not provide any at all.

## Thread Count

As of Crymap 2.0.0, Crymap is always entirely single-threaded.

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
