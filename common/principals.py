"""Principal normalization shared by every RBAC target.

export_cc_acls.py's UserV2:* merge (see its module docstring) can leave a
principal in the "UserV2:<id>" form Confluent Cloud's raw ACL API uses
internally for service accounts. Neither Confluent Cloud IAM v2 nor
Confluent Platform via MDS accepts that prefix; both expect the standard
"User:<id>" Kafka principal form. Every target needs the same normalization
before it emits a binding, so it lives here. Testing against mock_server.py
showed targets/cp_mds.py forwarding an unnormalized "UserV2:" principal
until this was factored out.
"""
from __future__ import annotations


def normalize(value: str) -> str:
    return "User:" + value.split(":", 1)[1] if value.startswith("UserV2:") else value
