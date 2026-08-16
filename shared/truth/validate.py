"""Integrity rules for a ground-truth file, checked against its log.

Every rule returns a message rather than raising, so one run reports every
problem in the dataset instead of stopping at the first. The verifier prints
the whole list; a non-empty list fails the build.
"""

from shared.truth.writer import CATEGORIES


def validate_records(records, log_ips):
    """Check truth records against the client addresses in their log.

    Args:
        records: iterable of truth record dicts, in file order.
        log_ips: iterable of the client address on each log line, in log order.
            Only the address is needed, so the caller can stream the log
            without materialising it.

    Returns:
        A list of human-readable failure messages. Empty means valid.
    """
    errors = []
    expected_line_no = 1
    log_iter = iter(log_ips)
    n_records = 0

    # Per client: the id currently in progress, and every id already closed.
    # An id reappearing after another intervened means the episode boundaries
    # are wrong, which is the thing instance_id exists to make checkable.
    current_id = {}
    closed_ids = {}

    for record in records:
        n_records += 1

        line_no = record.get("line_no")
        if line_no != expected_line_no:
            errors.append(
                f"line {expected_line_no}: line_no is {line_no!r}, "
                f"expected {expected_line_no} (must be contiguous from 1)"
            )
        expected_line_no += 1

        category = record.get("category")
        if category not in CATEGORIES:
            errors.append(
                f"line {n_records}: category {category!r} is not in the "
                f"controlled vocabulary"
            )

        client_ip = record.get("client_ip")
        try:
            log_ip = next(log_iter)
        except StopIteration:
            errors.append(
                f"line {n_records}: truth record count exceeds log line count"
            )
            log_ip = None
        else:
            if client_ip != log_ip:
                errors.append(
                    f"line {n_records}: truth client_ip {client_ip!r} does not "
                    f"match the log line address {log_ip!r}"
                )

        instance_id = record.get("instance_id")
        active = current_id.get(client_ip)
        if active != instance_id:
            if instance_id in closed_ids.setdefault(client_ip, set()):
                errors.append(
                    f"line {n_records}: instance_id {instance_id!r} reappears "
                    f"for client {client_ip!r} after {active!r} intervened; "
                    f"episode groups must be contiguous per client"
                )
            if active is not None:
                closed_ids[client_ip].add(active)
            current_id[client_ip] = instance_id

    remaining = sum(1 for _ in log_iter)
    if remaining:
        errors.append(
            f"count mismatch: log has {n_records + remaining} lines but truth "
            f"has {n_records} records"
        )

    return errors
