# Pull request

## Summary

- <!-- 1–3 bullets describing what this PR changes and why. -->

## Related finding or issue

<!-- Link to the PUNCHOUT.md item, audit finding ID, or GitHub issue this resolves.
     Use "n/a" if not applicable. -->

## Testing done

- Hardware board(s) exercised: <!-- e.g. pico2_4m, rp2350_geek_16m -->
- Integration tests run (`./run_tests.sh` or subset): <!-- pass/fail summary -->
- Unit tests (`cargo test -p pico2hsm-core`): <!-- pass/fail summary -->

## Checklist

- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy -p pico2hsm-core -- -D warnings` clean
- [ ] `PUNCHOUT.md` updated if this closes an open item
- [ ] `CHANGELOG.md` Unreleased section updated if user-facing
- [ ] Docs updated if behaviour changed

## License

This project uses inbound=outbound MIT. No CLA is required. By opening this PR
you agree that your contribution is MIT-licensed.
