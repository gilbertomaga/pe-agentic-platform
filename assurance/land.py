"""
Hand a bundle to the evidence store, and write down what came back.

Separate from assembling it on purpose. Assembly is about a change and has to be reproducible;
landing is an act with a time and a destination, and the receipt is the only part that records
when and where. Keeping them apart is what lets the bundle's digest be something a third party
can re-derive months later.

Exit codes are the interface, because this runs in a pipeline:

  0  the bundle is in the store
  1  the store refused it, and the change should be treated as unevidenced rather than passed

There is no delete here, and there is not going to be. The platform's credentials cannot remove
what it filed, and neither can its code. See assurance/system-of-record.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from assurance import sink


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Land an assurance bundle in the evidence store.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--bucket", help="the client's evidence bucket, with object lock on it")
    parser.add_argument("--prefix", default="assurance")
    parser.add_argument("--endpoint", default=None,
                        help="an S3 compatible endpoint, for a store that is not AWS")
    parser.add_argument("--retain-days", type=int, default=sink.DEFAULT_RETAIN_DAYS)
    parser.add_argument("--directory", type=Path,
                        help="a local directory instead; development only, not a record "
                             "of account, and the receipt says so")
    parser.add_argument("--receipt", type=Path, default=None)
    args = parser.parse_args(argv)

    if bool(args.bucket) == bool(args.directory):
        parser.error("name exactly one of --bucket and --directory")

    store = (sink.ObjectStore(args.bucket, args.prefix, args.retain_days, args.endpoint)
             if args.bucket else sink.FileSink(args.directory))

    payload = args.bundle.read_bytes()
    try:
        receipt = store.put(args.bundle.name, payload)
    except sink.SinkRefused as refused:
        print(f"REFUSED: {refused}", file=sys.stderr)
        return 1

    print(f"filed {receipt.name}")
    print(f"  {receipt.bytes} bytes, sha256 {receipt.digest}")
    print(f"  {receipt.location} ({receipt.mode}) at {receipt.stored_at}")

    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(receipt.as_json(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
