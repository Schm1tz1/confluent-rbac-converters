"""Principal normalization shared by every RBAC target.

export_cc_acls.py's UserV2:* merge (see its module docstring) can leave a
principal in the "UserV2:<id>" form Confluent Cloud's raw ACL API uses
internally for service accounts. No RBAC target -- Confluent Cloud IAM v2 or
Confluent Platform via MDS -- accepts that prefix; both expect the standard
"User:<id>" Kafka principal form. Normalizing it is therefore not a
per-target decision, just something every target needs done to it before
a binding is emitted (verified live against the mock CC and MDS APIs in
mock_server.py -- an unnormalized "UserV2:" principal was silently accepted
and forwarded by targets/cp_mds.py until this was factored out).
"""
from __future__ import annotations


def normalize(value: str) -> str:
    return "User:" + value.split(":", 1)[1] if value.startswith("UserV2:") else value
