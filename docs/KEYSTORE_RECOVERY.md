# Keystore recovery runbook (2.0)

What to do when a pico2hsm (2.0 firmware) refuses its keystore, and
what each way out costs.  The design is in [STORAGE_V2.md](STORAGE_V2.md)
(§8.3 formatting, §9.3 damage and recovery, §16 OD-1); the APDUs are in
[SC_HSM_APDU_REFERENCE.md](SC_HSM_APDU_REFERENCE.md) §3.29, "Storage V2 store
commands".

## Why a device refuses its keystore

The 2.0 keystore fails closed.  The device never silently drops a damaged
record or formats a store it does not recognise: that would let someone
who can swap or rewrite the SD card bring back a deleted key, or wipe the
device.  Instead, it refuses the store and waits for you.

Two things on the chip's **internal** flash (never on the SD card) decide
what the device accepts:

- the **binding block**: the store's identity, its key epochs, and the
  SC-HSM **SO-PIN**;
- the **anchor** in the counter log: how far the store's journal had got.

Because the SO-PIN lives in the binding block, it still works when the
store is refused.  Every recovery step below needs it, except formatting a
store the device cannot bind to at all.

## 1. Find out what happened

**On the display** (boards with a screen):

| Shows | Means |
|---|---|
| `E10 NO SD CARD` | No card, or the card does not answer.  Reseat it; the device retries at each boot. |
| `E11 STORAGE UNREADABLE` | The store is refused, or the binding block does not verify.  Read STORE STATUS. |
| `E12 FORMAT STORE NEEDED` | No 2.0 store: a 1.x keystore after the upgrade, or a card formatted on another device. |
| `Keystore READ-ONLY` (note) | OPEN DEGRADED mounted the store read-only (step 3). |

**From the host**, STORE STATUS needs no PIN.  With OpenSC (`-r` picks the
reader, see `opensc-tool --list-readers`):

```sh
opensc-tool -r 0 -s 00A404000BE82B0601040181C31F020100 -s 80545200
```

or `pico2hsm-tool store status`.  The response's first bytes are `state`,
`reason`, then `lost` (8 bytes, big-endian):

| `state` | `reason` | Situation | Go to |
|---|---|---|---|
| `00` | — | Up.  Nothing to do. | — |
| `01` | any | Read-only after OPEN DEGRADED. | 4 or 5 |
| `02` | `04` behind the anchor | The journal lacks `lost` records the device had acknowledged: an SD card that lost its last writes, or an older copy of the card or flash. | 2, then 3 |
| `02` | `05` damaged | A journal or index record fails its check. | 2, then 3 |
| `02` | `02` another store | The card holds a different store (another device's card, one formatted elsewhere). | 2 |
| `02` | `01` blank | The card is blank (a new or wiped card where the real one should be). | 2 |
| `02` | `03` no anchor | The counter log lost the anchor (e.g. after a downgrade to 1.x and back). | 6 |
| `02` | `07` read error | The store could not be read.  Reseat the card, reboot. | 2 |
| `03` | — | No 2.0 store, or the binding does not verify (a 1.x keystore; a store from before OTP provisioning, see 7). | 6 |
| `04` | — | A format that did not finish (it finishes at the next boot: reboot), or no storage key (an unprovisioned release build). | Reboot; if still `04`, [PROVISIONING.md](PROVISIONING.md) |

## 2. First: is the right card in?

On SD-card boards, the most common cause by far is a missing, swapped or
reseated card.  Nothing has been written while the store was refused, so:

1. Power off, put the device's own card back in, and power on.
2. Read STORE STATUS again.  If it says `00`, you are done.

A different card (`02`/`02`), a blank one (`02`/`01`) or a wrong one never
changes the device: its own card still mounts when it comes back.  Do not
format until you are sure the right card is gone for good.

## 3. OPEN DEGRADED: look before you decide

OPEN DEGRADED mounts a refused store **read-only**, as far as it verifies.
Keys work and can be exported; every change fails (`6581`) until a reboot,
ACCEPT STORE or FORMAT STORE.  Nothing is written to the store, so it is
always safe to try.  The open is counted in the counter log.

```sh
SO_PIN=3537363231383830   # your SO-PIN, hex (sc-hsm-tool --so-pin form)
opensc-tool -r 0 \
  -s 00A404000BE82B0601040181C31F020100 \
  -s 0020008808$SO_PIN \
  -s 80544F000D4F50454E2D4445475241444544
```

(`pico2hsm-tool store open-degraded`.)  The device then reloads every
applet, which ends the session: SELECT and VERIFY again before using keys.
STORE STATUS now reports `state 01` and the exact `lost` count.

Why the SO-PIN: the verifiable state can be older than the real one, so
it may still hold a key that was deleted later.  Only the SO-PIN may bring
that state into use.

## 4. Get the keys out (if you can)

While the store is read-only you can:

- **Export with the DKEK** (only if the device was initialised with DKEK
  shares): `sc-hsm-tool --wrap-key` for each key, then unwrap them into the
  device again after step 5 or 6.  See [SINGLE_DEVICE_SETUP.md](SINGLE_DEVICE_SETUP.md).
- **Rely on a domain peer** (cluster setups): peers hold the domain's keys;
  after recovery the device resyncs.  See [CLUSTER_PLAN_V3.md](CLUSTER_PLAN_V3.md).
- **Use the keys** for whatever must not wait (signing, decryption).

## 5. ACCEPT STORE: keep what is there

ACCEPT STORE makes the read-only state the store's new, read-write state.
Use it when the store is behind its anchor (`reason 04`) or damaged
(`reason 05`), you have looked at what OPEN DEGRADED mounted, and losing
the `lost` records is acceptable.

**What you give up:** the last `lost` changes the device had made.  A key
generated or imported in them is gone; a key **deleted** in them **comes
back**; an object changed in them reverts to its earlier version.  If a key
was deleted because it was compromised, delete it again right after.

You must send the `lost` count you were shown; a different count is
refused (`6A80`), so a store that changed under you is never accepted
blind.  With `lost` = 3:

```sh
opensc-tool -r 0 \
  -s 00A404000BE82B0601040181C31F020100 \
  -s 0020008808$SO_PIN \
  -s 80545300174143434550542D53544F52452D56320000000000000003
```

(`pico2hsm-tool store accept` reads the count, shows it and asks you to
confirm it.)  The re-index takes a few seconds on an SD card.  A power cut
during it is safe: the next boot finishes it, or finds the store refused
as before and you run steps 3 and 5 again.  The re-anchor is counted, with
the old and new journal positions, in the counter log; STORE STATUS
reports the count.

Not available for another store, a blank card or a lost anchor: those are
not this device's journal to accept.

## 6. FORMAT STORE: start again

FORMAT STORE replaces the store with a new, empty one.  **Every key of
every applet (SC-HSM, PIV, OpenPGP) is gone**, for good: the old store's
key epochs are destroyed with it.

It needs the SO-PIN, except when there is nothing to bind to (`state 03`:
a 1.x keystore, a store from another device or from before OTP
provisioning) or the store is refused and no SO-PIN was ever set.

```sh
opensc-tool -r 0 \
  -s 00A404000BE82B0601040181C31F020100 \
  -s 0020008808$SO_PIN \
  -s 80544E000F464F524D41542D53544F52452D5632
```

(`pico2hsm-tool store format`.)  The SO-PIN carries over: the next
INITIALIZE needs it.  Then set up the applets as on a new device, and
restore keys from DKEK backups or let domain peers resync.

On an SD-card board whose card is lost for good, put in a new card and
format it this way: the device adopts it.

## 7. After OTP provisioning

Provisioning the storage key into OTP changes the key everything on the
keystore is sealed under.  The store written before can't be opened
afterwards (`state 03`), by design: keys on an unprovisioned board were
never protected.  Export what you need **before** provisioning (step 4
works on an up store too), then FORMAT STORE after it.  See
[PROVISIONING.md](PROVISIONING.md).

## BOOTSEL cannot wipe the store

Since the 2.0 flash layout ([FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md)),
the binding, counter log, RSA pool and keystore are partitions closed to
the bootloader: from BOOTSEL, picotool can neither read nor erase them,
not even with a full-chip erase.  Recovery goes through the firmware
(the steps above) or SWD.  On a **development** board the partition table
itself can still be erased from BOOTSEL (`picotool erase -r 0x10000000
0x10001000`), which reopens everything; **production** tables close that
too.

## What never happens by itself

- No format: not of a blank, foreign, damaged or missing store.  Only a
  never-used device formats itself at first boot.
- No silent loss: a damaged record is never skipped; the store is refused
  and you decide.
- No rollback without the SO-PIN, and none that STORE STATUS and the
  counter log do not record.
