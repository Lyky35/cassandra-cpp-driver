# Native Protocol v5 Port Plan — cassandra-cpp-driver 2.17.1

Base: tag `2.17.1`, branch `proto-v5`, fork of `apache/cassandra-cpp-driver`.

Reference implementations used:
- `apache/cassandra` `doc/native_protocol_v5.spec` (trunk) — authoritative
- `datastax/java-driver` 4.19.x + `com.datastax.oss:native-protocol` 1.5.x
- `apache/cassandra-gocql-driver` 2.2.x
- `apache/cassandra-python-driver` 3.30.x

---

## 0. Current state: message bodies are done, framing is not

The driver has had `CPP-443 "Support for protocol v5"` since **2.7.0** (2019). That work
predates v5 going GA in Cassandra 4.0-beta5, and it covered only *message body* changes.
The v5 **framing format was never implemented**.

Consequence: the driver's "v5 beta" can only talk to pre-GA Cassandra 4.0 alphas, which
accepted bare 9-byte envelopes. Against any GA Cassandra 4.0+ node the connection breaks
immediately after `STARTUP`. `USE_BETA` (`0x10`) is also set on v5 frames, which GA servers
reject for a non-beta version.

### Already implemented (verify, don't rewrite)

| v5 feature | Location | Notes |
|---|---|---|
| `[int]` query flags in QUERY/EXECUTE | `src/statement.cpp:379-383`, `:416-420` | byte→int switch |
| `[int]` query flags in BATCH | `src/batch_request.cpp:159-163`, `:183-187` | **duplicated logic**, see §5.1 |
| PREPARE flags + `WITH_KEYSPACE` | `src/prepare_request.cpp:26-52` | v5/DSEv2 gated |
| EXECUTE `result_metadata_id` | `src/execute_request.cpp:29-49` | sends 2-byte zero when v4 |
| PREPARED `result_metadata_id` | `src/result_response.cpp:325-327` | |
| `METADATA_CHANGED` → `new_metadata_id_` | `src/result_response.cpp:240-248` | v5-gated |
| Duration type code `0x0015` | `include/cassandra.h:550` | |
| Duration *encode* (zigzag, m/d/ns) | `src/encode.cpp:45-83`, `src/types.hpp:65` | `CassDuration` struct |
| `CASS_FLAG_BETA 0x10` | `src/constants.hpp:72` | per-frame, set in `request_callback.cpp:72` |
| Capability gates | `src/protocol.cpp:29-33`, `:86-94` | single helper `is_protocol_at_least_v5_or_dse_v2` |
| Reactive downgrade | `src/connector.cpp:77-79`, `src/cluster_connector.cpp:277-291` | error-message sniffing |
| `USE_BETA` opt-in | `src/cluster_config.cpp:73-76` | `cass_cluster_set_use_beta_protocol_version` |

### Gaps, ordered by severity

| # | Gap | Impact |
|---|---|---|
| **1** | **No v5 framing format.** No CRC24, no CRC32, no frame header. `grep -ri "crc\|segment\|envelope" src/` hits only `src/third_party/minizip`. | **Blocker.** Cannot connect to C* 4.0+. |
| 2 | v5 is not a *valid* version. `ProtocolVersion::is_valid()` returns false for v5 (`src/protocol.cpp:65-69`), asserted in `tests/src/unit/tests/test_protocol_version.cpp:71-74`. `highest_supported()` returns V4. | v5 is opt-in only; any `is_valid()` guard silently rejects it. |
| 3 | No `USE_BETA` clearing. Flag still set for v5 frames. | GA servers may reject. |
| 4 | No proactive negotiation. SUPPORTED response is only cached (`src/connector.cpp:281-289`); protocol version is never read from it or from `system.peers.release_version`. | First connection attempt to a 4.0 node fails, then downgrade retries. |
| 5 | `NOW_IN_SECONDS` (`0x0100`) flag absent from `src/constants.hpp:74-83`. | Feature missing. |
| 6 | Duration *decode* missing. `Decoder::decode_vint` (`src/decoder.hpp:443-476`) is **unsigned — no zigzag**. `DataTypeDecoder` (`src/result_response.cpp:112-180`) has no duration branch; `0x0015` falls through to `SimpleDataTypeCache::by_value_type`. `cass_value_get_duration` exists (`include/cassandra.h:10700`) but has nothing to decode into. | Duration values are wrong/unusable. |
| 7 | `metadata_changed` payload position not verified against v5 ordering. | Latent — verify before trusting. |
| 8 | Integration tests default to Cassandra `3.11.6` (`tests/src/integration/options.cpp:26`), which has no v5. | No coverage; must retarget to 4.0+/4.1+. |
| 9 | **No compression at all** (no LZ4, no Snappy). | *Not a problem* — see §2.3. |

---

## Phase 1 — CRC primitives (new, self-contained, testable)

The driver has `md5.cpp`, `murmur3.cpp`, no CRC. Model on `gocql/crc.go` and
`cassandra/segment.py:23-58`.

New file `src/crc.hpp` / `src/crc.cpp`:

- `crc24(uint32_t header_data, size_t nbytes)` — init `0x875060`, poly `0x1974F0B`,
  MSB-first per byte, consumes the packed little-endian integer least-significant-byte first.
  Spec §2.1 line 132-133.
- `crc32(const char* data, size_t size)` — standard CRC-32 seeded with `0xFA2D55CA`
  (i.e. `crc32(prefix || data)`). Written **little-endian**, as a **trailer**, over the
  encoded (possibly compressed) payload.

No license concern: both are 20-line reference implementations already public in the
Apache-licensed gocql / Python driver sources.

## Phase 2 — v5 framing layer (the real work)

### 2.1 Format (spec §2.1, lines 96-134)

Two variants, both little-endian, max payload `2^17 - 1` = 131071 bytes.

**Uncompressed** — 6-byte header:
```
bits  0..16 (17)  payload_length
bit  17     (1)   isSelfContained
bits 18..23 (6)   padding (discard)
bits 24..47 (24)  CRC24 of the 3 header bytes
+ payload + CRC32 trailer (4 bytes, LE)
```

**LZ4-compressed** — 8-byte header:
```
bits  0..16  (17)  compressed_length
bits 17..33  (17)  uncompressed_length
bit  34      (1)   isSelfContained
bits 35..39  (5)   padding
bits 40..63  (24)  CRC24 of the 5 header bytes
+ payload + CRC32 of *compressed* payload
```
`uncompressed_length == 0` ⇒ use payload as-is, do not decompress.

### 2.2 New files

- `src/frame.hpp` / `src/frame.cpp` — `FrameHeader`, `encode_frame()`, `FrameDecoder`
  state machine (partial-header buffering, CRC verify, `isSelfContained`).
- `Connection` owns one `FrameDecoder`; one `bool startup_completed_` latch.

### 2.3 Scope decision: uncompressed only

The driver has **no compression support whatsoever** — no LZ4, no Snappy anywhere in `src/`
or `CMakeLists.txt`. Since v5 mandates STARTUP not carry compression until the frame codec
is live, and "only LZ4 is currently supported for v5" anyway, the correct minimal path is:

- Always emit the **uncompressed** 6-byte header.
- Never send `COMPRESSION` in STARTUP (already the case — no code exists).
- Leave the 8-byte header unimplemented; add a `#error`/guard if a compressor is ever wired in.

This removes LZ4 from the critical path entirely. Revisit only if compression is separately
requested.

### 2.4 Write path hook

`RequestCallback::write_frame` — `src/request_callback.cpp:58-99`. Currently builds the
9-byte envelope into `BufferVec`. After Phase 3 flips v5 on, wrap the assembled envelope
bytes in a frame before handing to `Socket::write`.

### 2.5 Read path hook

`Connection::on_read` — `src/connection.cpp:233-240` — loops
`response_->decode(pos, remaining)`. Insert the frame decoder *above* it:

```
on_read(buf, size)
  └─ frame_decoder_.decode(buf, size)   → yields zero or more complete envelope byte-ranges
       └─ for each envelope: ResponseMessage::decode(...)   (existing code, unchanged)
```

`ResponseMessage::decode` (`src/response.cpp:101-180`) stays as-is — it already parses the
classic 9-byte envelope correctly for any version. Envelopes may be split across frames
(non-self-contained), so the frame decoder must buffer and reassemble before handing down.
Reference: `Connection.process_io_buffer` / `_process_segment_buffer`,
`cassandra/connection.py:1181-1235`.

## Phase 3 — negotiation and version bookkeeping

### 3.1 Promote v5 to a first-class version

- `ProtocolVersion::is_valid()` — `src/protocol.cpp:65-69`. Change the bound from
  `highest_supported(is_dse())` to include v5. Currently v5 fails this, which means
  `cluster_connector.cpp:288` aborts with `CLUSTER_ERROR_INVALID_PROTOCOL` before it can
  downgrade. **Keep `is_beta()` returning true until §4 lands**, so existing
  `test_protocol_version.cpp:71-74` documents the change deliberately.
- `ProtocolVersion::highest_supported(bool)` — `src/protocol.cpp:51`. Return V5 for OSS.
  **Careful**: this value is also used by `previous()` (`src/protocol.cpp:81`) and by
  `cass_cluster_set_use_beta_protocol_version`.
- `ProtocolVersion::newest_beta()` — `src/protocol.cpp:57`. Only change once a v6 beta
  exists; leave at v5 for now.
- Update `tests/src/unit/tests/test_protocol_version.cpp:28-38`, `:71-74`.

### 3.2 Stop setting `USE_BETA` for v5

`src/request_callback.cpp:72-74`:
```cpp
if (version.is_beta()) flags |= CASS_FLAG_BETA;
```
Make this conditional on an explicit opt-in rather than `is_beta()`, so GA v5 does not
carry the flag. Note the Java driver inverted this the same way: `USE_BETA` is now set only
for v6 (`FrameCodec.computeFlags` compares against `ProtocolConstants.Version.BETA`).

### 3.3 Proactive version selection

Two viable strategies; **recommend (b)**.

**(a) Blind dial-and-downgrade** — what gocql does (`control.go:231-265`). One TCP connect
per candidate version, 5 → 4 → 3. Simple, needs no schema queries, but wastes a connection
per attempt and costs a round trip against non-Cassandra servers.

**(b) Infer from node release version** — what the Java driver does
(`DefaultProtocolVersionRegistry.highestCommon`, lines 114-220). The driver already reads
`system.peers` / `system.local` for topology, so this is cheap:

```
read release_version from system.local / system.peers
  >= 4.0  → V5
  >= 2.2  → V4
  >= 2.1  → V3
```
Do this *before* opening the first connection, or on the first `system.local` query.

### 3.4 Also handle the second downgrade trigger

gocql (`conn.go:402-430`) treats a **SUPPORTED frame arriving on stream 0** as "I don't speak
that version". Some servers do this instead of an ERROR. Add that to the downgrade predicate
in `src/cluster_connector.cpp:277-291`; the C++ `Connector` currently only sniffs the ERROR
message string `"Invalid or unsupported protocol version"` (`src/connector.cpp:77-79`).

### 3.5 Version string in SUPPORTED

Spec line 757-758: the SUPPORTED `PROTOCOL_VERSIONS` map is keyed `3/v3`, `4/v4`,
`5/v5-beta`. Once v5 is GA the key becomes `5/v5`. If §3.3(b) is chosen, this map becomes the
authoritative source and the release-version heuristic is only a fallback — prefer the map.

## Phase 4 — remaining message-body gaps

### 4.1 Duration decode (gap #6)

- Add **zigzag** to the vint path. `src/decoder.hpp:443-476` `decode_vint` is unsigned;
  add `decode_vint_zigzag(int64_t&)` using `(n >> 1) ^ -(n & 1)`, mirroring
  `encode_zig_zag` already used in `src/encode.cpp`.
- Add a `CASS_VALUE_TYPE_DURATION` branch to `DataTypeDecoder::decode()`
  (`src/result_response.cpp:112-180`) that reads three zigzag vints into a `CassDuration`
  (`src/types.hpp:65`), rather than falling through to `by_value_type`.
- Add public `cass_row_get_duration` / `cass_collection_get_duration` /
  `cass_tuple_get_duration` to match the existing setters in `include/cassandra.h`
  (`cass_collection_append_duration:7691`, `cass_tuple_set_duration:8127`,
  `cass_user_type_set_duration:9146`).
- Tests: `tests/src/unit/tests/test_encode.cpp` has no duration cases today.

### 4.2 `NOW_IN_SECONDS` (gap #5)

- Add `#define CASS_QUERY_FLAG_NOW_IN_SECONDS 0x00000100` to `src/constants.hpp:74-83`.
  It only fits because v5 widens flags to `[int]`.
- Encode `[int]` **last**, after `<keyspace>` — ordering is load-bearing. Both
  `src/statement.cpp:385-424` and `src/batch_request.cpp:168-190`.
- Add `cass_statement_set_now_in_seconds()` alongside the existing
  `cass_statement_set_keyspace()` (`src/statement.cpp:406-408`).

### 4.3 Verify `metadata_changed` ordering (gap #7)

Spec order in RESULT/Rows metadata is:
`<flags> <columns_count> [<paging_state>] [<new_metadata_id>] [<global_table_spec>? <col_specs>]`

Check `ResultResponse::decode_metadata` (`src/result_response.cpp:232-299`) reads
`new_metadata_id_` *after* `paging_state` (`:260-265`) and *before* the column specs
(`:267+`). The report suggests it does, but this was never validated against a real v5 server
— treat as unverified.

## Phase 5 — refactor the duplicated v5 conditionals

### 5.1 Flags encoding is copy-pasted

`src/statement.cpp:379-383` + `:416-420` and `src/batch_request.cpp:159-163` + `:183-187`
each inline `if (version >= CASS_PROTOCOL_VERSION_V5)`. Any further flags work must touch all
four sites. Extract a single helper in `src/protocol.cpp` next to
`is_protocol_at_least_v5_or_dse_v2` (`src/protocol.cpp:29-33`), e.g.
`ProtocolVersion::query_flags_size()` mirroring Java's
`QueryOptions.queryFlagsSize()`.

### 5.2 Collapse the capability gates

`supports_set_keyspace()` and `supports_result_metadata_id()` (`src/protocol.cpp:86-94`) are
byte-identical. Merge into a single `supports_v5_features()`, then grow named predicates for
each new feature (`supports_now_in_seconds`, `supports_duration`, `supports_framing`). Keep
the DSE bit handling in `is_protocol_at_least_v5_or_dse_v2` — it correctly treats
`0x40 | n` as DSE.

## Phase 6 — public API / config

- `cass_cluster_set_use_beta_protocol_version` (`src/cluster_config.cpp:73-76`): keep for
  source compat, but deprecate — v5 is no longer beta.
- `cass_cluster_set_protocol_version` (`src/cluster_config.cpp:47-68`) currently refuses
  anything but beta when `use_beta_protocol_version` is set, and errors if a version
  above `highest_supported` is requested. Re-check these guards against the new bounds.
- `cass_cluster_set_protocol_version` should start accepting `CASS_PROTOCOL_VERSION_V5`
  without the beta flag.
- Update `docs.yaml`, `CHANGELOG.md`, `topics/`.

## Phase 7 — tests

- **Retarget integration tests**: `tests/src/integration/options.cpp:26` defaults to
  Cassandra `3.11.6`. Set `4.0.x`/`4.1.x` and add a v5-vs-v4 matrix.
- **Mock server**: `tests/src/unit/mockssandra.hpp:912-933` already accepts versions 1-5 and
  rejects invalid ones at `mockssandra.cpp:2006-2015` with the exact error string
  `"Invalid or unsupported protocol version"` (`mockssandra.cpp:1325`) that the real
  downgrade path sniffs for. It needs to learn the **frame format** to serve v5 responses.
- Fix `tests/src/unit/tests/test_protocol_version.cpp:71-74` (asserts v5 is invalid).
- New unit tests: CRC24/CRC32 vectors against the Python driver's `test_segment.py`; frame
  header round-trip incl. the `uncompressed_length == 0` passthrough and multi-frame
  (non-self-contained) reassembly; duration vint round-trip.
- `tests/src/unit/tests/test_decoder.cpp:30-31` defaults to `highest_supported()`, which
  becomes v5 — check for fallout.

---

## Sequencing

```
Phase 1  CRC primitives                 (isolated, no deps)
Phase 2  Framing layer                  (depends on 1; largest; do NOT merge with 3)
Phase 3  Negotiation + version bounds   (depends on 2 to be testable against 4.0)
Phase 4  Duration decode, now_in_seconds (independent of 2/3 — can parallelize)
Phase 5  Deduplicate v5 conditionals     (do before Phase 4b to avoid touching 4 sites)
Phase 6  Public API + docs
Phase 7  Tests
```

Phases 1+2 are the critical path and are strictly ordered. Phase 4 is independent and can be
done in parallel or first as a warm-up. **Do not start Phase 3 before Phase 2** — you cannot
validate negotiation without a working frame codec.

## Risks

1. **Framing is the whole job.** Phases 4-6 are hours; Phase 2 is days. Any plan that
   budgets them equally is wrong.
2. **Buffering bugs are silent.** A mis-sized frame header corrupts the stream rather than
   erroring. The reassembly path for non-self-contained frames is the most likely place to
   get this wrong, and it only triggers on envelopes > 128 KiB — which is exactly the large
   result sets that matter. Test it explicitly.
3. **libuv read boundaries don't align with frames.** `on_read` gets arbitrary chunk sizes.
   `ResponseMessage::decode` already handles partial headers; the frame decoder must too.
4. **DSE interop.** `is_protocol_at_least_v5_or_dse_v2` treats `0x42` (DSEv2) as v5-capable,
   so DSEv2 takes the same code paths. DSE 6.7/6.8 map to Cassandra 4.0
   (`tests/src/integration/ccm/cass_version.hpp:503-504`) — verify DSE still passes.
5. **The existing beta path has never run against GA C* 4.0.** Treat every "already
   implemented" item in the table above as *unverified*, not done. Phase 2 is what will
   first exercise them, so expect to find bugs there.