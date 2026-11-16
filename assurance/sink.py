"""
Where a bundle lands, and why that is not the platform's own disk.

Steve's note on Module 3 was that the trail lives in a file in my repository. That is the whole
problem in one sentence. An audit record held by the party being audited is worth what that
party's word is worth, and the point of the record was to not have to take anyone's word.

So the platform hands the evidence over. It writes into a bucket in the client's own account,
with object lock in compliance mode and a retention period the client sets, and the credentials
it writes with can do nothing else. `s3:PutObject`, no delete, no overwrite, no lifecycle. Once a
bundle lands, this platform cannot change it or remove it, and neither can the client's
administrator, and neither can the account root, until the retention expires. That is what makes
the producer of the record an acceptable producer of the record.

Two things follow, and both are in the code rather than in the prose:

  The sink checks the bucket is actually locked before it writes. Object lock is bucket
  configuration, not a flag on the write, so a sink pointed at an ordinary bucket would write
  happily and produce a perfect looking audit record anybody could delete, with nothing about the
  write to tell you. It refuses instead. Fail closed, same as the policy and the supply chain.

  The flags are built by a pure function and asserted as data, exactly like the sandbox's
  container flags, because the retention mode is the control. `--object-lock-mode COMPLIANCE` is
  not a tuning parameter: GOVERNANCE mode can be bypassed by anyone holding one extra permission,
  which on an audit store is the difference between write once and write usually.

The local sink is for development and for keeping a copy with the build. It refuses to overwrite,
which is the most a filesystem can offer and considerably less than the client's store offers.
See assurance/system-of-record.md for what the client configures, and docs/decisions.md D11.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

#: Not GOVERNANCE. GOVERNANCE retention is removable by a caller with s3:BypassGovernanceRetention,
#: so a store configured that way is write once for people who do not have that permission, which
#: is not a property worth putting in front of an auditor.
LOCK_MODE = "COMPLIANCE"

DEFAULT_RETAIN_DAYS = 365


class SinkRefused(Exception):
    """The bundle was not stored, and the change should be treated as unevidenced."""


@dataclass(frozen=True)
class Receipt:
    """What came back from storing a bundle.

    The timestamp lives here and not in the bundle, deliberately. When a bundle was filed is a
    fact about the filing; what it says about the change has to stay byte for byte reproducible,
    or its digest is not something anyone else can check.
    """
    name: str
    digest: str
    bytes: int
    location: str
    stored_at: str
    mode: str

    def as_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)


def _receipt(name: str, payload: bytes, location: str, mode: str) -> Receipt:
    return Receipt(
        name=name,
        digest=hashlib.sha256(payload).hexdigest(),
        bytes=len(payload),
        location=location,
        stored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        mode=mode,
    )


class FileSink:
    """A directory. For development, and for keeping a copy beside the build that made it.

    It will not overwrite. That is all a filesystem can promise, and it is named `development`
    in the receipt so that nothing downstream mistakes a copy on a build agent for the record of
    account. A bundle is content addressed, so the same bundle landing twice is the same bytes
    and is allowed; different bytes under a name already taken is somebody rewriting history.
    """

    mode = "development"

    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def put(self, name: str, payload: bytes) -> Receipt:
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.directory / name
        if target.exists() and target.read_bytes() != payload:
            raise SinkRefused(
                f"{name} is already stored with different contents. A bundle is named by its own "
                "digest, so this means something is writing a different bundle under a name that "
                "is taken, which is the one thing an evidence store must not allow.")
        target.write_bytes(payload)
        return _receipt(name, payload, str(target), self.mode)


def retain_until(days: int = DEFAULT_RETAIN_DAYS, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def lock_check_argv(bucket: str, endpoint: str | None = None) -> list[str]:
    """Ask the bucket whether it is locked. Run before the first write, not after a problem."""
    argv = ["aws", "s3api", "get-object-lock-configuration", "--bucket", bucket]
    return argv + (["--endpoint-url", endpoint] if endpoint else [])


def put_argv(bucket: str, key: str, source: Path, until: str,
             endpoint: str | None = None) -> list[str]:
    """The write. These flags are the control, so they are asserted in tests as data."""
    argv = [
        "aws", "s3api", "put-object",
        "--bucket", bucket,
        "--key", key,
        "--body", str(source),
        "--content-type", "application/json",
        "--object-lock-mode", LOCK_MODE,
        "--object-lock-retain-until-date", until,
    ]
    return argv + (["--endpoint-url", endpoint] if endpoint else [])


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    if shutil.which(argv[0]) is None:
        raise SinkRefused(
            f"{argv[0]} is not on PATH, so the bundle cannot be handed to the evidence store. "
            "A change whose evidence was not filed is unevidenced; it is not a change that "
            "quietly passed.")
    return subprocess.run(argv, capture_output=True, text=True)


class ObjectStore:
    """The client's evidence store: an object store with write once retention.

    S3 shaped, and the API is the same on the compatible implementations, so the client is not
    obliged to be on AWS for this to be the thing they already run.
    """

    mode = "write-once"

    def __init__(self, bucket: str, prefix: str = "assurance",
                 retain_days: int = DEFAULT_RETAIN_DAYS, endpoint: str | None = None):
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.retain_days = retain_days
        self.endpoint = endpoint

    def key_for(self, name: str, on: datetime | None = None) -> str:
        """Partition by the day it was filed, so the store is queryable without reading it.

        An auditor asks what shipped in a period, not what one run id did, and a flat prefix
        makes that question a full listing of every bundle ever filed. Dated prefixes are what
        every object store query engine already understands, so the answer is a prefix rather
        than a scan. The date is the filing date, which is why it is here and not in the bundle:
        the bundle has to stay reproducible, and a receipt is allowed to know what day it is.
        """
        on = on or datetime.now(timezone.utc)
        parts = [self.prefix] if self.prefix else []
        parts += [on.strftime("%Y"), on.strftime("%m"), on.strftime("%d"), name]
        return "/".join(parts)

    def check(self) -> str:
        """Refuse a bucket that is not locked, before anything is written into it."""
        done = _run(lock_check_argv(self.bucket, self.endpoint))
        if done.returncode != 0:
            raise SinkRefused(
                f"{self.bucket} has no object lock configuration, or it could not be read.\n"
                f"  {done.stderr.strip()}\n"
                "Writing an audit bundle into a bucket anybody can empty produces a record that "
                "looks exactly like evidence and is not. Enable object lock on the bucket, in "
                "compliance mode, before pointing this at it. See assurance/system-of-record.md.")
        return done.stdout.strip()

    def put(self, name: str, payload: bytes) -> Receipt:
        self.check()
        key = self.key_for(name)
        with tempfile.TemporaryDirectory() as workspace:
            body = Path(workspace) / "bundle.json"
            body.write_bytes(payload)
            done = _run(put_argv(self.bucket, key, body,
                                 retain_until(self.retain_days), self.endpoint))
        if done.returncode != 0:
            raise SinkRefused(f"the evidence store refused the bundle:\n  {done.stderr.strip()}")
        return _receipt(name, payload, f"s3://{self.bucket}/{key}", self.mode)
