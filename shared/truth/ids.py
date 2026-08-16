"""Request ids -- the key the access log and the truth file are joined on.

Kept here rather than beside either producer because the driver, the tag proxy
and every future project's equivalents must all mint ids the same way. An id
that is unique within one component and not across them would join cleanly and
label wrongly.
"""

import secrets

#: 16 bytes, hex-encoded. Two properties matter, and neither is negotiable.
#: The id must contain no whitespace, because it is the first field of a tagged
#: log line and the join splits that line on its first space. And a collision
#: between two ids is a silently mislabelled line, so the space is made large
#: enough that collisions stop being a consideration rather than merely
#: becoming unlikely -- the tagged log is an intermediate file, so the width
#: costs nothing that ships.
_ID_BYTES = 16


def new_request_id():
    """Return a fresh request id: 32 lowercase hex characters."""
    return secrets.token_hex(_ID_BYTES)
