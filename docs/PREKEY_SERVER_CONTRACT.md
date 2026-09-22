# Prekey Server Allocation Contract

**Status:** security requirement for production integration.

The crypto library can generate and locally consume one-time EC/PQ prekeys, but
"one-time" is an end-to-end property only if the public prekey service allocates
each uploaded public key at most once.

## Security invariant

For every `(recipient_device, prekey_kind, prekey_id)`:

```text
successful_allocations <= 1
```

Concurrent bundle fetches must never receive the same one-time public key.

This is stronger than "delete the row soon after reading it". The read and
removal/reservation must be one atomic database transaction.

## Required allocation model

The device uploads an inventory exported by:

- `PrekeyStore::public_ec_inventory()`
- `PrekeyStore::public_pq_inventory()`

The server stores each item under a unique key such as:

```text
(recipient_device_id, kind, prekey_id)
```

A bundle request atomically *claims* one EC OPK and one PQ OPK. If the
inventory is empty, the server may return the current reusable signed / last-
resort material according to protocol policy.

Conceptual SQL for a database with row locking:

```sql
BEGIN;

SELECT prekey_id, public_key
FROM one_time_prekeys
WHERE recipient_device_id = :device
  AND kind = 'EC'
ORDER BY prekey_id
LIMIT 1
FOR UPDATE SKIP LOCKED;

DELETE FROM one_time_prekeys
WHERE recipient_device_id = :device
  AND kind = 'EC'
  AND prekey_id = :selected_id;

COMMIT;
```

A database that supports atomic `DELETE ... RETURNING`, compare-and-swap, or a
transactional queue should prefer that primitive.

## Bad implementation

```text
request A: SELECT OPK 51
request B: SELECT OPK 51
request A: DELETE OPK 51
request B: DELETE OPK 51
```

Both clients now believe they received a one-time key.

## Correct concurrent behavior

```text
request A: claim OPK 51
request B: claim OPK 52
```

or, if 51 was the last OPK:

```text
request A: claim OPK 51
request B: receive no OPK / last-resort fallback
```

## Idempotency and retries

Network retries complicate allocation. A client request should carry a random
idempotency token. The server must persist:

```text
(recipient_device_id, request_token) -> exact allocated bundle
```

A retry with the same token returns the same allocation; a different token
must not obtain an already-claimed OPK.

This prevents a timeout after a successful database commit from accidentally
burning multiple keys merely because the requester retried.

## Upload rules

1. `(device, kind, prekey_id)` is unique.
2. Re-upload of identical public bytes for the same id is idempotent.
3. Re-upload of *different* bytes/signature for an existing id is rejected.
4. The server never invents, transforms, or re-signs client prekeys.
5. A consumed public OPK is never reinserted by ordinary retry logic.
6. Inventory counts are monitored so clients can replenish before exhaustion.

## Required stress test

Run at least 100 logical contacts × 100 concurrent initiation requests with
random retries/timeouts. Assert:

```text
duplicate successful OPK allocation = 0
```

Also test exhaustion, replenishment, duplicate request tokens, server crash
between claim and response, and delayed first-message delivery.

## Boundary

The library now exposes public one-time-key inventories, but it cannot enforce
the server database transaction from inside a mobile process. Production status
therefore requires evidence that the actual prekey service implements this
contract.
