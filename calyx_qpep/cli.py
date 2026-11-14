#!/usr/bin/env python3
"""
Command-Line Interface (CLI) for the Calyx QPEP Protocol.
"""
import argparse
import sys
from .protocol import CalyxQPEPProtocol
from .passphrase import analyze_passphrase


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="calyx-qpep",
        description="Calyx QPEP v1.0 Quantum Proof Encryption Protocol CLI (Calyx Labs Inc.)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_chk = sub.add_parser("check-passphrase", help="Validate a passphrase against Calyx QPEP QPKD-Argon policy")
    p_chk.add_argument("--passphrase", required=True)

    p_kg = sub.add_parser("keygen", help="Generate a new Calyx QPEP key pair and export .qpkrf files")
    p_kg.add_argument("--name", required=True)
    p_kg.add_argument("--email", required=True)
    p_kg.add_argument("--passphrase", required=True)
    p_kg.add_argument("--pub-out", required=True)
    p_kg.add_argument("--priv-out", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "check-passphrase":
        res = analyze_passphrase(args.passphrase)
        print(f"Valid: {res.is_valid}")
        return 0 if res.is_valid else 1
    if args.cmd == "keygen":
        kr = CalyxQPEPProtocol.generate_keypair(args.name, args.email, args.passphrase)
        CalyxQPEPProtocol.export_qpkrf(kr, args.passphrase, include_private=False, output_path=args.pub_out)
        CalyxQPEPProtocol.export_qpkrf(kr, args.passphrase, include_private=True, output_path=args.priv_out)
        print(f"Generated Calyx QPEP Key-ID: {kr.key_id}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
