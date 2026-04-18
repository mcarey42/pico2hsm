# Third-Party Notices

The **pico2hsm** project is distributed under the terms of the MIT License
(see [`LICENSE`](LICENSE)).  pico2hsm links against a number of third-party
open-source crates, the large majority of which are themselves offered under
`MIT OR Apache-2.0` dual license terms.  For those crates we elect the MIT
option and no additional attribution is required.

A small number of dependencies are offered under permissive licenses other
than MIT.  They are listed below and their license terms are reproduced (or
linked) as required by those licenses.  This file is a best-effort record;
the authoritative license text for each crate is the `LICENSE*` file shipped
inside that crate's source distribution on <https://crates.io>.

## Apache-2.0-only dependencies

### codespan-reporting v0.11.1

- **Crate:** <https://crates.io/crates/codespan-reporting>
- **Repository:** <https://github.com/brendanzab/codespan>
- **License:** Apache-2.0
- **License text:** <https://github.com/brendanzab/codespan/blob/master/LICENSE>
- **Usage:** Transitive dependency pulled in on the embedded (`thumbv8m.main-none-eabihf`)
  target only, via the RP2350 HAL / build-time diagnostic tooling.  Not
  included in host-side builds.

> Copyright (c) 2019 Brendan Zabarauskas
>
> Licensed under the Apache License, Version 2.0 (the "License"); you may
> not use this file except in compliance with the License.  You may obtain
> a copy of the License at
>
>   <http://www.apache.org/licenses/LICENSE-2.0>
>
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.

## BSD-3-Clause / BSD-2-Clause dependencies

The following crates are offered under BSD terms.  They are listed here for
completeness; each crate ships its own `LICENSE` file in its source tree with
the full copyright notice.  The BSD license only requires that the copyright
notice, conditions list, and disclaimer be retained in redistributions — the
terms below are satisfied by distribution of the unmodified crate sources
via Cargo / crates.io, which this project does not alter.

- `subtle` (BSD-3-Clause) — Isis Lovecruft, Henry de Valence
- `curve25519-dalek` (BSD-3-Clause) — Isis Lovecruft, Henry de Valence
- `ed25519-dalek` (BSD-3-Clause) — Isis Lovecruft, Henry de Valence
- `x25519-dalek` (BSD-3-Clause) — Isis Lovecruft, dalek-cryptography contributors
- `zerocopy` (BSD-2-Clause OR Apache-2.0 OR MIT — we select MIT)

## Unicode-3.0 dependencies

- `unicode-ident` v1.x — `(MIT OR Apache-2.0) AND Unicode-3.0`.  The
  Unicode data tables are governed by the Unicode License v3
  (<https://www.unicode.org/license.txt>).  Redistribution of the unmodified
  crate satisfies the terms; no additional notice is required in downstream
  binaries.

## Unlicense dependencies

- `byteorder` — `Unlicense OR MIT`.  We select MIT.

---

All remaining direct and transitive dependencies are licensed under
`MIT OR Apache-2.0` (or a compatible combination).  For the complete
dependency tree run:

```sh
cargo tree --workspace --prefix none --format "{p} {l}"
```
