# The evidence store

What the client configures, in their own account, so that the platform can hand over an audit
record it is then unable to touch. Nothing here is specific to a cloud provider beyond the API
names; the properties are the point and the object stores that offer them all offer them the
same way.

There are no account identifiers, bucket names or role names in this file, and there will not be.
The configuration belongs to whoever runs the account. This describes the shape it has to have.

## The property that matters

The platform writes. It cannot read back, cannot overwrite, cannot delete, and cannot change the
rules. That is not a policy the platform enforces on itself, which would be worth nothing, it is
the account owner's configuration enforced against the platform's credentials.

## The bucket

Object lock enabled **at creation**. It cannot be turned on afterwards on most implementations,
which is the sort of thing that is discovered late and expensively.

Default retention in **compliance** mode, for the period the client's own records policy
requires. Compliance rather than governance: governance retention can be removed by any caller
holding `s3:BypassGovernanceRetention`, so a governance bucket is write once for people who do
not have one extra permission. That is not a sentence anybody wants to say to a risk function.

Versioning on, which object lock requires anyway. A write to an existing key creates a new
version rather than replacing one, and the retained version stays retained.

No lifecycle rule that expires objects before the retention period, and no rule that transitions
them somewhere the auditor cannot read.

## How it is laid out, so it can be queried

    <prefix>/<year>/<month>/<day>/<run id>.<bundle digest>.json

An auditor asks what shipped in a period, not what one run identifier did. A flat prefix turns
that question into a listing of every bundle ever filed, so bundles are partitioned by the day
they were filed and the question becomes a prefix. That is the layout every object store query
engine already understands, so the client can point their own tooling at it without the platform
providing a query service, which is one less thing of ours between their risk function and their
evidence.

The date is the filing date rather than anything inside the bundle. The bundle has to stay
reproducible byte for byte, so it carries no clock; the receipt is allowed to know what day it
is, and the key is part of the filing.

## The platform's credentials

A role the platform assumes, with one permission on one prefix:

    s3:PutObject

Not `s3:DeleteObject`, not `s3:DeleteObjectVersion`, not `s3:PutObjectRetention`, not
`s3:PutBucketObjectLockConfiguration`, not `s3:PutLifecycleConfiguration`. The platform must not
be able to shorten a retention it set, or it can set one and then think better of it.

Read access belongs to the client's risk function and their auditors, not to the platform. The
platform has no reason to read its own evidence back, and a credential that can read the whole
audit history is a credential worth stealing.

## Why the platform checks before it writes

Object lock is configuration on the bucket, not a flag on the write. A sink pointed at an
ordinary bucket writes successfully, returns a clean receipt, and produces something that looks
exactly like an audit record and is deletable by anyone with access. Nothing about the write
tells you. So `assurance.sink.ObjectStore.check` reads the lock configuration first and refuses
the whole operation if it is not there. A change whose evidence could not be filed is an
unevidenced change, which is a different and more useful finding than a change that passed.

## Retention, and the thing retention does not solve

Retention keeps the bundle. It does not keep the key that would let you prove the bundle was the
one filed at the time, and it does not stop somebody filing a second, friendlier bundle for the
same run later. Two things reduce that. The bundle is named by its own digest, so a different
bundle is a different object rather than a replacement. And the bundle quotes the trail's head
anchor, so a bundle filed later for the same run carries a chain position, and a chain position
that has gone backwards is visible to whoever reads both.

What would close it properly is the store recording its own receipt, countersigned, at the time
of the write. That is the client's store's job and not something this platform can assert on its
behalf, so it is named here rather than claimed anywhere else.
