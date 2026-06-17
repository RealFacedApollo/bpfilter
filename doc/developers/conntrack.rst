Conntrack
=========

Connection tracking (conntrack) adds stateful filtering to bpfilter via the
``ct.conntrack`` matcher. Maps are host-global and pinned under
``$BPFFS/bpfilter/ct/``. Programs on individual chains share these maps.

For rule syntax and examples, see :doc:`../usage/bfcli` (Connection tracking
section).

Program reload
--------------

Rule updates reload BPF programs, not conntrack maps.

``bf_chain_update()`` calls ``bf_cgen_update()``, which:

1. Validates the key-normalization version in the pinned ``ct_meta`` map.
2. Compiles and loads the new program.
3. Atomically swaps the attached program with ``bf_link_update()``.

Pinned flow maps (``ct_map_tcp``, ``ct_map_any``, and related maps) are
untouched. Established flows keep their entries and continue to match
``ct.conntrack`` rules after reload.

Failure modes follow a fail-safe model: compilation, verifier, or link-update
errors leave the previous program attached. A key-normalization version
mismatch rejects the reload before any new program is loaded.

Rule removal and connection drain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removing an ACCEPT rule does not immediately delete conntrack entries. While an
entry remains, packets are still classified as ``ESTABLISHED``. A leading
``ct.conntrack`` fast-path rule keeps those flows alive until timeout or LRU
eviction.

Key-normalization version gate
------------------------------

Flow map keys depend on a stable normalization algorithm. If the algorithm or
``ct_key`` layout changes between releases, old entries would not match new
lookups.

``BF_CT_KEY_NORM_VERSION`` in ``ct.h`` records the current algorithm revision
in the ``ct_meta`` pinned map. ``bf_ct_maps_check_reload()`` compares the
pinned value against the build constant before ``bf_cgen_update()`` proceeds.

On mismatch, reload fails with an error instructing the operator to remove
pinned maps under ``$BPFFS/bpfilter/ct/`` before attaching a new program.
There is no in-tree ``bfcli ct flush`` command yet; delete the pinned
directory manually.

GC supervisor contract
----------------------

Userspace GC runs outside the datapath via ``bfcli ct gc sweep`` (one-shot) or
``bfcli ct gc run`` (loop). Each ``bf_ct_gc_sweep_batch()`` call writes
``last_sweep_ns`` into ``ct_meta``.

An external supervisor can poll heartbeat health with::

    bfcli ct gc status

Output is machine-parseable::

    key_norm_version=1
    last_sweep_ns=...
    stale=0

``stale=1`` when ``last_sweep_ns`` is zero or older than 120 seconds
(``BF_CT_GC_STALE_THRESHOLD_NS``). Restart ``bfcli ct gc run`` when stale.

Tests
-----

- Unit: ``tests/unit/libbpfilter/ct/meta.c``, ``gc.c``
- E2E: ``tests/e2e/conntrack/tcp_established.sh``, ``tcp_reload.sh``

Operator validation
-------------------

``libbpfilter`` validates conntrack chains at load and map-init time. There is
no ``bfcli`` command yet to tune map sizes or timeouts; sizing uses build-time
defaults unless overridden through the library API.

Hook compatibility (error)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Chains that create or consult conntrack state cannot attach to
``BF_HOOK_XDP``. This includes:

- explicit ``ct.conntrack`` matchers
- ``ACCEPT`` rules without ``NOTRACK`` (implicit entry creation)
- ``ACCEPT`` chain policy

Use ``BF_HOOK_TC_INGRESS`` / ``BF_HOOK_TC_EGRESS`` for stateful rules, or mark
rules ``NOTRACK`` for stateless XDP chains.

``bf_ct_validate_hook_compat()`` runs in ``bf_chain_new()`` and
``bf_program_new()``.

Chain policy warnings
~~~~~~~~~~~~~~~~~~~~~

``bf_ct_warn_chain_policy()`` emits ``bf_warn()`` messages at chain load time:

- **NEW without ESTABLISHED/RELATED:** a ``ct.conntrack`` rule accepts
  ``NEW`` traffic but no rule fast-paths ``ESTABLISHED`` or ``RELATED``.
  Return traffic re-evaluates the full chain on every packet.
- **ACCEPT policy without CT rules:** policy is ``ACCEPT`` but no
  ``ct.conntrack`` matchers are defined. Adding an ``ESTABLISHED`` fast-path
  later will not match existing flows.
- **NOTRACK contradiction:** ``ct.conntrack`` matchers exist, policy is not
  ``ACCEPT``, and every ``ACCEPT`` rule is marked ``NOTRACK``. No entries are
  created; ``ESTABLISHED`` rules never match.

Map memory warning
~~~~~~~~~~~~~~~~~~

``bf_ct_warn_map_memory()`` runs during ``bf_ct_maps_init()`` and warns when:

- estimated CT map memory exceeds 25% of ``MemAvailable`` from
  ``/proc/meminfo``
- any flow map ``max_entries`` is below 16384

Timeout bounds
~~~~~~~~~~~~~~

``bf_ct_timeouts_clamp()`` enforces per-field min/max bounds when timeouts are
written to the pinned ``ct_timeouts`` map. Out-of-range values are clamped and
logged. Defaults are already within bounds; clamping matters when a future
configure API sets custom values.
