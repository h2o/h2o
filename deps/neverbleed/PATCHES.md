# Local modifications to the vendored copy of neverbleed

`deps/neverbleed` is a vendored copy of [kazuho/neverbleed](https://github.com/kazuho/neverbleed). It is
tracked in this repository as ordinary files (it is not a git submodule), so that the fork can carry
local changes; the changes have to be re-applied when the vendored copy is updated.

## 1. Reject the deletion of a key that is not in use (VULN-007)

**Status:** applied in this repository. Upstream: not reported yet.

The daemon keeps the private keys in a table of slots, and a slot that is in use holds a key while a
slot that is empty holds the index of the next empty slot, the two being stored in a union. The
`del_pkey` command of the protocol releases a slot: it frees the key and puts the slot onto the list
of empty slots.

The command did not check whether the slot was in use. A `del_pkey` command for a slot that had
already been released therefore did two harmful things: it called `EVP_PKEY_free()` on the value
that the union held at that moment, which was the index of the next empty slot rather than a
pointer, and it put the slot onto the list of empty slots a second time, so that the same slot could
be handed out twice and a key that was still in use could be freed.

The slot is now checked before the key is released. The check walks the list of empty slots, which is
bounded by the number of slots; if the list turns out to be corrupt, the command is refused rather
than guessed. The client side additionally clears the key index once it has sent the command, so
that a key object cannot release the same key twice.

Note that the lifetime of a key in the daemon is not reference counted: a key that is imported into
the worker carries the index of the slot that holds the key, and releasing it from the worker
releases the slot. Two objects that refer to the same slot (which is what an export/import round
trip produces) therefore still release the slot twice, but the second release is now refused by the
daemon instead of corrupting its heap.

**Files touched:** `neverbleed.c` (`is_slot_in_use()`, `del_pkey_stub()`, `keymgmt_free()`,
`ec_keymgmt_free()`).

## 2. Sign the data with the one-shot call

**Status:** applied in this repository. Upstream: not reported yet.

The OpenSSL 3 provider variant of the daemon obtained the size of the signature by calling
`EVP_DigestSignFinal()` with a null buffer, and then called it a second time to obtain the signature. The second
call fails for the ECDSA keys, as the first call already consumed the signing operation, and the daemon then
responds with an empty signature. A TLS handshake that uses an ECDSA certificate therefore failed, and the cipher
suites that use one did not work at all. The RSA cipher suites were unaffected.

Use the one-shot `EVP_DigestSign()` call instead. The comment in the code noted that the `Update` -> `Final` chain was
used because the ED25519 keys cannot be loaded; as the one-shot call behaves identically for every other key type,
the chain is not needed.

**Files touched:** `neverbleed.c` (`digestsign_stub()`).
