"""Compare the derived access log against the one Apache wrote independently.

The shipped access.log is the tagged log with its id prefix removed. Apache
also writes an ordinary combined log of the same requests, from the same
processes, at the same moments. If deriving lost or reordered anything, these
two files diverge.

The comparison is strictly positional. Sorting first, or comparing as multisets,
would report agreement in exactly the case the design exists to guard against --
two processes interleaving their writes to the two files differently. A
divergence here is a real finding and gets published as one.
"""

from typing import NamedTuple


class Agreement(NamedTuple):
    agreed: int
    derived_lines: int
    #: None when the reference file is absent -- which is a fact to report, not
    #: an absence of disagreement.
    reference_lines: object
    first_divergence: object

    @property
    def identical(self):
        return (self.reference_lines is not None
                and self.agreed == self.derived_lines == self.reference_lines)

    def summary(self):
        if self.reference_lines is None:
            return (f"{self.derived_lines} derived lines; Apache's own combined "
                    f"log was not available to compare against")
        if self.identical:
            return f"{self.agreed}/{self.derived_lines} lines agreed, in order"
        return (f"{self.agreed}/{self.derived_lines} lines agreed; Apache's own "
                f"log has {self.reference_lines} lines; first divergence at "
                f"line {self.first_divergence}")


def _read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")


def compare_logs(derived_path, reference_path):
    """Compare two log files line by line, in order.

    Args:
        derived_path: the shipped access.log, derived from the tagged log.
        reference_path: the combined log Apache wrote for itself.

    Returns:
        An Agreement. Counting continues past the first divergence so the
        report can say how much of the file agreed, not merely where it
        stopped.
    """
    derived = list(_read_lines(derived_path))

    try:
        reference = list(_read_lines(reference_path))
    except FileNotFoundError:
        return Agreement(agreed=0, derived_lines=len(derived),
                         reference_lines=None, first_divergence=None)

    agreed = 0
    first_divergence = None
    for number, (left, right) in enumerate(zip(derived, reference), start=1):
        if left == right:
            agreed += 1
        elif first_divergence is None:
            first_divergence = number

    if first_divergence is None and len(derived) != len(reference):
        first_divergence = min(len(derived), len(reference)) + 1

    return Agreement(agreed=agreed, derived_lines=len(derived),
                     reference_lines=len(reference),
                     first_divergence=first_divergence)
