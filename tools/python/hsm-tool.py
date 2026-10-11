#!/usr/bin/env python3
"""hsm-tool — pico2hsm host-side provisioning CLI.

Usage::

    python hsm-tool.py [--reader N] [--debug] <subcommand> [options]

Run ``hsm-tool.py --help`` or ``hsm-tool.py <subcommand> --help`` for details.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

import click
from tqdm import tqdm

# Ensure the package is importable when run from this directory
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))

from pico2hsm import Pico2HSM
from pico2hsm.errors import (
    APDUError,
    DeviceNotFoundError,
    PINError,
    Pico2HSMError,
)
from pico2hsm import protocol as proto
from pico2hsm.crypto import (
    derive_dkek_share,
    generate_self_signed_cert,
    xor_dkek_shares,
)
from pico2hsm.dkek import DkekExchange
from pico2hsm.storage import get_storage_status, trigger_resync

# ---------------------------------------------------------------------------
# Shared CLI context
# ---------------------------------------------------------------------------

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--reader", "-r", default=0, show_default=True, help="PCSC reader index")
@click.option("--debug", "-d", is_flag=True, default=False, help="Dump raw APDUs")
@click.pass_context
def cli(ctx: click.Context, reader: int, debug: bool) -> None:
    """pico2hsm — Host-side provisioning and management tool.

    Communicates with the HSM over USB CCID (PCSC) or direct USB HID.
    """
    ctx.ensure_object(dict)
    ctx.obj["reader"] = reader
    ctx.obj["debug"] = debug

    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")


def _open_hsm(ctx: click.Context) -> Pico2HSM:
    """Open and return a connected HSM, exiting with a friendly message on failure."""
    reader = ctx.obj["reader"]
    debug = ctx.obj["debug"]
    try:
        hsm = Pico2HSM(reader_index=reader, debug=debug)
        hsm.connect()
        return hsm
    except DeviceNotFoundError as exc:
        click.echo(f"Error: Device not found — {exc}", err=True)
        click.echo(
            "Tip: Check that the pico2hsm is plugged in and that you have "
            "PCSC daemon running (pcscd) or the correct udev rules for USB HID.",
            err=True,
        )
        sys.exit(1)
    except Pico2HSMError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _handle_apdu_error(exc: APDUError) -> None:
    click.echo(f"APDU error: SW={exc.sw:04X}  {exc.description}", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--so-pin", prompt="SO-PIN", hide_input=True, help="Security Officer PIN")
@click.option("--pin", prompt="User PIN", hide_input=True, confirmation_prompt=True, help="User PIN")
@click.option("--label", default="pico2hsm", show_default=True, help="HSM label")
@click.option("--dkek-shares", default=1, show_default=True, type=click.IntRange(1, 8), help="Number of DKEK shares")
@click.option("--options", default=0, show_default=True, help="Options byte (hex)", type=lambda x: int(x, 0))
@click.pass_context
def init(ctx: click.Context, so_pin: str, pin: str, label: str, dkek_shares: int, options: int) -> None:
    """Initialize HSM: set SO-PIN, user PIN, label and DKEK share count."""
    with _open_hsm(ctx) as hsm:
        click.echo(f"Initializing HSM '{label}' with {dkek_shares} DKEK share(s)…")
        apdu = proto.build_initialize(so_pin, pin, label, options, dkek_shares)
        try:
            hsm.select_applet()
            hsm.transmit(apdu)
            click.echo("HSM initialized successfully.")
        except PINError:
            click.echo("Error: PIN rejected during initialization.", err=True)
            sys.exit(1)
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

_KEY_TYPE_MAP = {
    "rsa2048": (proto.KEY_TYPE_RSA, 2048, b""),
    "rsa4096": (proto.KEY_TYPE_RSA, 4096, b""),
    "ec-p256": (proto.KEY_TYPE_EC, 256, proto.OID_SECP256R1),
    "ec-p384": (proto.KEY_TYPE_EC, 384, proto.OID_SECP384R1),
    "ec-p521": (proto.KEY_TYPE_EC, 521, proto.OID_SECP521R1),
    "ec-k256": (proto.KEY_TYPE_EC, 256, proto.OID_SECP256K1),
    "aes128": (proto.KEY_TYPE_AES, 128, b""),
    "aes192": (proto.KEY_TYPE_AES, 192, b""),
    "aes256": (proto.KEY_TYPE_AES, 256, b""),
}


@cli.command()
@click.option("--type", "key_type", required=True,
              type=click.Choice(list(_KEY_TYPE_MAP.keys()), case_sensitive=False),
              help="Key type to generate")
@click.option("--key-id", required=True, type=click.IntRange(1, 255), help="Key reference (1-255)")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def keygen(ctx: click.Context, key_type: str, key_id: int, pin: str) -> None:
    """Generate a key pair or symmetric key on the HSM."""
    algo, size, curve_oid = _KEY_TYPE_MAP[key_type.lower()]

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        # Verify PIN
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        click.echo(f"Generating {key_type.upper()} key (id={key_id})…")
        try:
            if algo == proto.KEY_TYPE_AES:
                apdu = proto.build_generate_aes_key(key_id, size)
            else:
                apdu = proto.build_generate_keypair(key_id, algo, curve_oid)

            with tqdm(total=1, desc="Generating", unit="key") as pbar:
                response, _ = hsm.transmit(apdu)
                pbar.update(1)

            click.echo(f"Key {key_id} ({key_type.upper()}) generated successfully.")
            if algo != proto.KEY_TYPE_AES and response:
                pub_key = proto.parse_public_key(response)
                click.echo(f"Public key ({len(pub_key)} bytes): {pub_key[:16].hex()}…")
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# keyimport
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--key-id", required=True, type=click.IntRange(1, 255), help="Key reference")
@click.option("--file", "key_file", required=True, type=click.Path(exists=True), help="Wrapped key blob file")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def keyimport(ctx: click.Context, key_id: int, key_file: str, pin: str) -> None:
    """Import a DKEK-wrapped key blob into the HSM."""
    with open(key_file, "rb") as fh:
        key_data = fh.read()

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        click.echo(f"Importing key blob ({len(key_data)} bytes) as key {key_id}…")
        try:
            apdu = proto.build_import_key(key_id, key_data)
            hsm.transmit(apdu)
            click.echo(f"Key {key_id} imported successfully.")
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@cli.command(name="list")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def list_keys(ctx: click.Context, pin: str) -> None:
    """List all key objects stored on the HSM."""
    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        try:
            apdu = proto.build_list_keys()
            response, _ = hsm.transmit(apdu)
            keys = proto.parse_list_keys(response)
        except APDUError as exc:
            _handle_apdu_error(exc)
            return

    if not keys:
        click.echo("No keys found.")
        return

    click.echo(f"{'ID':>4}  {'Type':<8}  {'Size':>6}  {'Label'}")
    click.echo("-" * 40)
    for k in keys:
        click.echo(f"{k['key_id']:>4}  {k['key_type']:<8}  {k['key_size']:>6}  {k['label']}")


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

_ALGO_MAP = {
    "ec-raw": proto.ALGO_EC_RAW,
    "ec-sha256": proto.ALGO_EC_SHA256,
    "rsa-raw": proto.ALGO_RSA_RAW,
    "rsa-pkcs1": proto.ALGO_RSA_PKCS1,
    "rsa-pkcs1-sha256": proto.ALGO_RSA_PKCS1_SHA256,
    "rsa-pss": proto.ALGO_RSA_PSS,
    "rsa-pss-sha256": proto.ALGO_RSA_PSS_SHA256,
}


@cli.command()
@click.option("--key-id", required=True, type=click.IntRange(1, 255), help="Key reference")
@click.option("--algo", required=True, type=click.Choice(list(_ALGO_MAP.keys()), case_sensitive=False),
              help="Signature algorithm")
@click.option("--data", "data_file", type=click.Path(exists=True), help="File to sign (stdin if omitted)")
@click.option("--output", "-o", type=click.Path(), help="Output signature file (stdout if omitted)")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def sign(ctx: click.Context, key_id: int, algo: str, data_file: Optional[str], output: Optional[str], pin: str) -> None:
    """Sign data with an HSM key."""
    if data_file:
        with open(data_file, "rb") as fh:
            data = fh.read()
    else:
        data = click.get_binary_stream("stdin").read()

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        algo_byte = _ALGO_MAP[algo.lower()]
        click.echo(f"Signing {len(data)} bytes with key {key_id} ({algo})…", err=True)
        try:
            apdu = proto.build_sign(key_id, algo_byte, data)
            signature, _ = hsm.transmit(apdu)
        except APDUError as exc:
            _handle_apdu_error(exc)
            return

    if output:
        with open(output, "wb") as fh:
            fh.write(signature)
        click.echo(f"Signature ({len(signature)} bytes) written to {output}")
    else:
        sys.stdout.buffer.write(signature)


# ---------------------------------------------------------------------------
# verify-pin
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def verify_pin(ctx: click.Context, pin: str) -> None:
    """Test PIN verification without performing any operation."""
    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
            click.echo("PIN verification succeeded.")
        except PINError as exc:
            click.echo(f"PIN verification failed: {exc}", err=True)
            sys.exit(1)
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# change-pin
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--old-pin", prompt="Current PIN", hide_input=True, help="Current user PIN")
@click.option("--new-pin", prompt="New PIN", hide_input=True, confirmation_prompt=True, help="New user PIN")
@click.pass_context
def change_pin(ctx: click.Context, old_pin: str, new_pin: str) -> None:
    """Change the user PIN."""
    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            apdu = proto.build_change_pin(old_pin, new_pin)
            hsm.transmit(apdu)
            click.echo("PIN changed successfully.")
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# certload
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--fid", required=True, help="EF file identifier (hex, e.g. CE01)", type=lambda x: int(x, 16))
@click.option("--file", "cert_file", required=True, type=click.Path(exists=True), help="Certificate file (PEM or DER)")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def certload(ctx: click.Context, fid: int, cert_file: str, pin: str) -> None:
    """Load a certificate into an EF on the HSM."""
    from pico2hsm.crypto import load_certificate, cert_to_der

    with open(cert_file, "rb") as fh:
        raw = fh.read()

    cert = load_certificate(raw)
    der = cert_to_der(cert)
    click.echo(f"Loading certificate ({len(der)} bytes) into EF {fid:04X}…")

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        try:
            # Select EF then write
            hsm.transmit(proto.build_select_ef(fid))
            apdu = _encode_update_binary(der)
            with tqdm(total=len(der), desc="Writing", unit="B", unit_scale=True) as pbar:
                hsm.transmit(apdu)
                pbar.update(len(der))
            click.echo(f"Certificate written to EF {fid:04X}.")
        except APDUError as exc:
            _handle_apdu_error(exc)


def _encode_update_binary(data: bytes) -> bytes:
    from pico2hsm.protocol import _encode_apdu, INS_UPDATE_BINARY
    return _encode_apdu(0x00, INS_UPDATE_BINARY, 0x00, 0x00, data)


# ---------------------------------------------------------------------------
# certdump
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--fid", required=True, help="EF file identifier (hex)", type=lambda x: int(x, 16))
@click.option("--output", "-o", type=click.Path(), help="Output file (PEM); stdout if omitted")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def certdump(ctx: click.Context, fid: int, output: Optional[str], pin: str) -> None:
    """Dump a certificate from an EF on the HSM."""
    from pico2hsm.crypto import load_certificate, cert_to_pem

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        try:
            hsm.transmit(proto.build_select_ef(fid))
            apdu = proto.build_read_binary(fid)
            der_data, _ = hsm.transmit(apdu)
        except APDUError as exc:
            _handle_apdu_error(exc)
            return

    if not der_data:
        click.echo(f"No data in EF {fid:04X}.", err=True)
        sys.exit(1)

    try:
        cert = load_certificate(der_data)
        pem = cert_to_pem(cert)
    except Exception as exc:
        click.echo(f"Failed to parse certificate: {exc}", err=True)
        sys.exit(1)

    if output:
        with open(output, "wb") as fh:
            fh.write(pem)
        click.echo(f"Certificate written to {output}")
    else:
        sys.stdout.buffer.write(pem)


# ---------------------------------------------------------------------------
# dkek-init
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--shares", default=1, show_default=True, type=click.IntRange(1, 8), help="Total shares in the ceremony")
@click.option("--share-index", default=1, show_default=True, type=click.IntRange(1, 8), help="This share's index")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output file for share blob")
@click.option("--passphrase", prompt="Share passphrase", hide_input=True, confirmation_prompt=True,
              help="Passphrase to protect this DKEK share")
@click.pass_context
def dkek_init(ctx: click.Context, shares: int, share_index: int, output: str, passphrase: str) -> None:
    """Initialize DKEK: generate a DKEK share protected by a passphrase."""
    import base64

    click.echo(f"Generating DKEK share {share_index}/{shares}…")
    share_bytes, salt = derive_dkek_share(passphrase)

    import struct as _struct
    blob = salt + share_bytes
    encoded = base64.b64encode(blob).decode()

    with open(output, "w") as fh:
        fh.write(f"# pico2hsm DKEK share {share_index}/{shares}\n")
        fh.write(f"# Salt + share (base64)\n")
        fh.write(encoded + "\n")

    click.echo(f"DKEK share written to {output}")
    click.echo("Keep this file and passphrase SAFE.  Together they protect your HSM keys.")


# ---------------------------------------------------------------------------
# dkek-import
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--file", "share_file", required=True, type=click.Path(exists=True), help="DKEK share blob file")
@click.option("--passphrase", prompt="Share passphrase", hide_input=True, help="Passphrase for this share")
@click.option("--pin", prompt="SO-PIN", hide_input=True, help="Security Officer PIN")
@click.pass_context
def dkek_import(ctx: click.Context, share_file: str, passphrase: str, pin: str) -> None:
    """Import a DKEK share into the HSM."""
    import base64

    with open(share_file) as fh:
        lines = [l.strip() for l in fh if not l.startswith("#") and l.strip()]
    if not lines:
        click.echo("Error: Empty share file.", err=True)
        sys.exit(1)

    blob = base64.b64decode(lines[0])
    salt = blob[:16]
    share_bytes, _ = derive_dkek_share(passphrase, salt=salt)

    from pico2hsm.protocol import build_extras
    from pico2hsm.storage import EXTRAS_STORAGE_STATUS  # noqa: F401

    EXTRAS_DKEK_IMPORT = 0x12
    apdu = build_extras(EXTRAS_DKEK_IMPORT, share_bytes)

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        try:
            hsm.transmit(apdu)
            click.echo("DKEK share imported successfully.")
        except APDUError as exc:
            _handle_apdu_error(exc)


# ---------------------------------------------------------------------------
# dkek-exchange
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--mode", required=True, type=click.Choice(["usb-local", "tcp-server", "tcp-client"]),
              help="Exchange mode")
@click.option("--peer", default=None, help="Remote peer address:port (for tcp-client mode)")
@click.option("--port", default=7890, show_default=True, help="TCP port (for tcp-server mode)")
@click.option("--target-reader", default=1, show_default=True, type=int,
              help="Reader index for target HSM (usb-local mode)")
@click.option("--so-pin", prompt="SO-PIN", hide_input=True, help="SO-PIN (the exchange requires it on both HSMs)")
@click.pass_context
def dkek_exchange(ctx: click.Context, mode: str, peer: Optional[str], port: int, target_reader: int, so_pin: str) -> None:
    """Exchange DKEK with another HSM (V2 mutual-auth protocol).

    Both HSMs must already have each other's device key enrolled (enroll-peer).
    """
    exchange = DkekExchange()

    if mode == "usb-local":
        source_reader = ctx.obj["reader"]
        click.echo(f"Local USB exchange: reader {source_reader} -> reader {target_reader}")
        with Pico2HSM(reader_index=source_reader, debug=ctx.obj["debug"]) as source:
            source.connect()
            source.select_applet()
            source.transmit(proto.build_verify_so_pin(so_pin))
            with Pico2HSM(reader_index=target_reader, debug=ctx.obj["debug"]) as target:
                target.connect()
                target.select_applet()
                target.transmit(proto.build_verify_so_pin(so_pin))
                exchange.exchange_local_usb(source, target)
        click.echo("DKEK exchanged successfully.")

    elif mode == "tcp-server":
        with _open_hsm(ctx) as source:
            source.select_applet()
            source.transmit(proto.build_verify_so_pin(so_pin))
            click.echo(f"Waiting for peer on port {port}…")
            exchange.exchange_tcp_server(source, port=port)
        click.echo("DKEK sent to remote peer.")

    elif mode == "tcp-client":
        if not peer:
            click.echo("Error: --peer <host:port> required for tcp-client mode.", err=True)
            sys.exit(1)
        host, _, port_str = peer.rpartition(":")
        peer_port = int(port_str) if port_str else 7890
        with _open_hsm(ctx) as target:
            target.select_applet()
            target.transmit(proto.build_verify_so_pin(so_pin))
            click.echo(f"Connecting to {host}:{peer_port}…")
            exchange.exchange_tcp_client(target, server_host=host, server_port=peer_port)
        click.echo("DKEK received and imported.")


# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--target", required=True, type=int, help="Reader index of the target HSM")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN for both HSMs")
@click.pass_context
def backup(ctx: click.Context, target: int, pin: str) -> None:
    """Backup keystore to another HSM by exchanging DKEK then cloning key blobs."""
    click.echo(f"Backing up from reader {ctx.obj['reader']} to reader {target}…")
    exchange = DkekExchange()

    with Pico2HSM(reader_index=ctx.obj["reader"], debug=ctx.obj["debug"]) as source:
        source.connect()
        source.select_applet()
        source.transmit(proto.build_verify_pin(pin))

        with Pico2HSM(reader_index=target, debug=ctx.obj["debug"]) as dest:
            dest.connect()
            dest.select_applet()
            dest.transmit(proto.build_verify_pin(pin))

            click.echo("Step 1/2: Exchanging DKEK…")
            exchange.exchange_local_usb(source, dest)

            click.echo("Step 2/2: Cloning key blobs…")
            # List keys on source and export/import each
            resp, _ = source.transmit(proto.build_list_keys())
            keys = proto.parse_list_keys(resp)

            with tqdm(total=len(keys), desc="Keys", unit="key") as pbar:
                for key in keys:
                    kid = key["key_id"]
                    try:
                        blob, _ = source.transmit(proto.build_export_key(kid))
                        dest.transmit(proto.build_import_key(kid, blob))
                    except APDUError as exc:
                        click.echo(f"\nWarning: Failed to clone key {kid}: SW={exc.sw:04X}", err=True)
                    pbar.update(1)

    click.echo("Backup complete.")


# ---------------------------------------------------------------------------
# storage-status
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def storage_status(ctx: click.Context) -> None:
    """Show storage health: chips, RAID state, bad sectors."""
    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            status = get_storage_status(hsm)
        except Pico2HSMError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    click.echo("=== Storage Status ===")
    click.echo(f"Total keys    : {status.total_keys}")
    cap_mb = status.total_capacity_bytes / (1024 * 1024)
    used_mb = status.used_bytes / (1024 * 1024)
    click.echo(f"Capacity      : {cap_mb:.1f} MiB")
    click.echo(f"Used          : {used_mb:.1f} MiB ({status.used_pct:.1f}%)")
    click.echo(f"Overall health: {'OK' if status.healthy else 'DEGRADED'}")
    click.echo()

    if status.chips:
        click.echo("--- Chips ---")
        for chip in status.chips:
            click.echo(f"  Chip {chip.index}: {chip.status_str()}")
        click.echo()

    if status.mirror_pairs:
        click.echo("--- Mirror Pairs ---")
        for pair in status.mirror_pairs:
            click.echo(
                f"  Pair {pair.pair_index}: chips {pair.primary_chip}+{pair.secondary_chip}"
                f"  [{pair.state_str()}]"
            )


# ---------------------------------------------------------------------------
# storage-resync
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--chip", required=True, type=click.IntRange(0, 15), help="Chip index to resync")
@click.option("--pin", prompt="User PIN", hide_input=True, help="User PIN")
@click.pass_context
def storage_resync(ctx: click.Context, chip: int, pin: str) -> None:
    """Trigger RAID resync after chip/card replacement."""
    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        try:
            hsm.transmit(proto.build_verify_pin(pin))
        except PINError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        click.echo(f"Triggering resync for chip {chip}…")
        try:
            trigger_resync(hsm, chip)
            click.echo("Resync triggered.  The firmware will rebuild in the background.")
        except Pico2HSMError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


EXTRAS_FW_VERSION = 0x01
EXTRAS_BOARD_ID = 0x02
EXTRAS_CAPABILITIES = 0x03


@cli.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Print HSM info: firmware version, board, capabilities."""
    from pico2hsm.protocol import build_extras

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()

        def _get(sub: int) -> bytes:
            try:
                data, _ = hsm.transmit(build_extras(sub))
                return data
            except APDUError:
                return b""

        fw = _get(EXTRAS_FW_VERSION)
        board = _get(EXTRAS_BOARD_ID)
        caps = _get(EXTRAS_CAPABILITIES)

    click.echo("=== pico2hsm Info ===")
    if fw:
        if len(fw) >= 3:
            click.echo(f"Firmware version : {fw[0]}.{fw[1]}.{fw[2]}")
        else:
            click.echo(f"Firmware version : {fw.hex()}")
    else:
        click.echo("Firmware version : (not available)")

    click.echo(f"Board            : {board.decode('ascii', errors='replace') if board else '(not available)'}")

    if caps:
        cap_flags = int.from_bytes(caps[:4], "big") if len(caps) >= 4 else 0
        cap_names = []
        if cap_flags & 0x01:
            cap_names.append("RSA")
        if cap_flags & 0x02:
            cap_names.append("EC")
        if cap_flags & 0x04:
            cap_names.append("AES")
        if cap_flags & 0x08:
            cap_names.append("BIP32")
        if cap_flags & 0x10:
            cap_names.append("STORAGE-RAID")
        click.echo(f"Capabilities     : {', '.join(cap_names) if cap_names else 'none detected'}")
    else:
        click.echo("Capabilities     : (not available)")

    click.echo()
    available = Pico2HSM.list_devices()
    click.echo(f"Available readers ({len(available)}):")
    for i, dev in enumerate(available):
        marker = " <-- selected" if i == ctx.obj["reader"] else ""
        click.echo(f"  [{i}] {dev}{marker}")


# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--name", required=True, help="Human-readable name for this device")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output PEM file path")
@click.pass_context
def enroll(ctx: click.Context, name: str, output: str) -> None:
    """Enroll a device by reading and saving its P-256 identity public key."""
    from pico2hsm.enrollment import DeviceEnrollment

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        info = DeviceEnrollment.get_device_info(hsm)
        DeviceEnrollment.save_pubkey_pem(info.pubkey, output)
        click.echo(f"Device: {name}")
        click.echo(f"Fingerprint: {info.fingerprint}")
        click.echo(f"Generation: {info.generation}")
        click.echo(f"Public key saved to: {output}")
        click.echo("")
        click.echo("Add this to your dkek-daemon.yaml peers section:")
        click.echo(f'  - name: "{name}"')
        click.echo(f"    role: secondary")
        click.echo(f"    public_key_file: {output}")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------


def _open_reader(reader_index: int, debug: bool = False) -> Pico2HSM:
    """Open and connect a Pico2HSM at the given reader index."""
    hsm = Pico2HSM(reader_index=reader_index, debug=debug)
    hsm.connect()
    return hsm


def _empty_config():
    """Return a minimal PeerConfig for config-less operation."""
    from pico2hsm.config import PeerConfig
    return PeerConfig(peers=[])


@cli.command()
@click.option("--primary-reader", type=int, required=True, help="Reader index for primary HSM")
@click.option("--secondary-reader", type=int, default=None, help="Reader index for secondary HSM (local USB)")
@click.option("--to", "peer_name", default=None, help="Named peer for TCP sync (requires --config)")
@click.option("--config", "config_file", default=None, type=click.Path(exists=True), help="Peer config YAML")
@click.option("--quorum", default=1, type=int, help="Quorum required before syncing offline nodes")
@click.pass_context
def sync(ctx: click.Context, primary_reader: int, secondary_reader: Optional[int],
         peer_name: Optional[str], config_file: Optional[str], quorum: int) -> None:
    """Sync DKEK from primary to secondary HSM."""
    from pico2hsm.config import PeerConfig
    from pico2hsm.state import StatePersistence
    from pico2hsm.sync import SyncManager

    debug = ctx.obj["debug"]
    config = PeerConfig.load(config_file) if config_file else None
    persistence = StatePersistence()
    persistence.load()
    manager = SyncManager(config or _empty_config(), persistence, quorum)

    primary = _open_reader(primary_reader, debug=debug)
    try:
        primary.select_applet()
        if secondary_reader is not None:
            secondary = _open_reader(secondary_reader, debug=debug)
            try:
                secondary.select_applet()
                result = manager.sync_local(primary, secondary)
                if result.success:
                    click.echo(f"Sync complete: {result.message}")
                else:
                    click.echo(f"Sync failed: {result.message}", err=True)
                    raise SystemExit(1)
            finally:
                secondary.disconnect()
        elif peer_name and config:
            manager.sync_tcp_to_peer(primary, peer_name)
        else:
            click.echo("Specify --secondary-reader or --to with --config", err=True)
            raise SystemExit(1)
    finally:
        primary.disconnect()


# ---------------------------------------------------------------------------
# export-key
# ---------------------------------------------------------------------------


@cli.command("export-key")
@click.option("--key-id", required=True, type=int, help="Key reference (1-254)")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output blob file (.p2hk)")
@click.pass_context
def export_key_cmd(ctx: click.Context, key_id: int, output: str) -> None:
    """Export a DKEK-wrapped key to a file."""
    from pico2hsm.key_transfer import export_key as _export

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        _export(hsm, key_id, output)
        click.echo(f"Key {key_id} exported to {output}")


# ---------------------------------------------------------------------------
# import-key
# ---------------------------------------------------------------------------


@cli.command("import-key")
@click.option("--key-id", required=True, type=int, help="Key reference to store imported key")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Blob file (.p2hk)")
@click.pass_context
def import_key_cmd(ctx: click.Context, key_id: int, input_path: str) -> None:
    """Import a DKEK-wrapped key from a file."""
    from pico2hsm.key_transfer import import_key as _import

    with _open_hsm(ctx) as hsm:
        hsm.select_applet()
        _import(hsm, key_id, input_path)
        click.echo(f"Key imported to slot {key_id}")


# ---------------------------------------------------------------------------
# daemon
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--config", required=True, type=click.Path(exists=True), help="Peer config YAML")
@click.option("--pid-file", default=None, type=click.Path(), help="PID file path")
@click.option("--foreground", is_flag=True, default=False, help="Stay in foreground (default: daemonize)")
@click.option("--quorum", default=1, type=int, help="Quorum required before syncing offline nodes")
@click.pass_context
def daemon(ctx: click.Context, config: str, pid_file: Optional[str],
           foreground: bool, quorum: int) -> None:
    """Run the DKEK sync daemon."""
    from pico2hsm.config import PeerConfig
    from pico2hsm.daemon import DkekDaemon

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    cfg = PeerConfig.load(config)
    d = DkekDaemon(cfg, quorum_required=quorum)

    if not foreground:
        # Unix double-fork daemonize
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
        sys.stdin = open(os.devnull)
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

    d.run(pid_file=pid_file)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
