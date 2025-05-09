from enum import IntEnum
import json
import hashlib

from kcwarden.custom_types import result_headers
from kcwarden.custom_types.keycloak_object import Dataclass


class Severity(IntEnum):
    """
    The severity of an audit result.
    Based on the CVSS severities.
    """

    Info = 0  # Matches _None_ in CVSS
    Low = 2
    Medium = 5
    High = 7
    Critical = 9


class Result:
    def __init__(
        self,
        severity: Severity,
        offending_object: Dataclass,
        short_description: str,
        long_description: str,
        reference: str,
        reporting_auditor: str,
        additional_details: dict | None = None,
    ):
        self._severity = severity
        self._offending_object = offending_object
        self._reporting_auditor = reporting_auditor
        self._short_description = short_description
        self._long_description = long_description
        self._reference = reference
        self._additional_details = additional_details or dict()

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def offending_object(self) -> Dataclass:
        return self._offending_object

    @property
    def additional_details(self) -> dict:
        return self._additional_details

    def __lt__(self, other: "Result"):
        return self.severity < other.severity

    def __gt__(self, other: "Result"):
        return self.severity > other.severity

    def __le__(self, other: "Result"):
        return self.severity <= other.severity

    def __ge__(self, other: "Result"):
        return self.severity >= other.severity

    def get_reporting_auditor(self) -> str:
        return self._reporting_auditor

    def get_fingerprint(self) -> str:
        # This function generates a unique-but-constant fingerprint that covers
        # the salient fields of the result. This should stay identical over multiple
        # runs, assuming the result stays identical. We guarantee this by creating
        # a string representing the relevant parts of the finding and hashing it.
        fp_dict = {
            "realm": str(self._offending_object.get_realm().get_name()),
            "entityname": str(self._offending_object.get_name()),
            "entitytype": str(self._offending_object.get_type()),
            "auditor": str(self._reporting_auditor),
            "details": self._additional_details,
        }

        return hashlib.sha256(json.dumps(fp_dict, sort_keys=True).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            result_headers.FINGERPRINT: self.get_fingerprint(),
            result_headers.SEVERITY_NAME: self.severity.name,
            result_headers.REALM_NAME: self._offending_object.get_realm().get_name(),
            result_headers.ENTITY_NAME: self._offending_object.get_name(),
            result_headers.ENTITY_TYPE_NAME: self._offending_object.get_type(),
            result_headers.REPORTING_AUDITOR_NAME: self._reporting_auditor,
            result_headers.SHORT_DESCRIPTION_NAME: self._short_description,
            result_headers.LONG_DESCRIPTION_NAME: self._long_description,
            result_headers.REFERENCE_NAME: self._reference,
            result_headers.ADDITIONAL_DETAILS_NAME: self._additional_details,
        }

    def __str__(self) -> str:
        return f"""{self._offending_object} {self.severity.name}: {self._short_description}

{self._long_description}

Additional Details: 
{json.dumps(self._additional_details, indent=4)}

Reported by: {self._reporting_auditor}"""


def get_severity_by_name(severity_name: str) -> Severity:
    try:
        return Severity[severity_name.lower().capitalize()]
    except KeyError:
        raise ValueError(
            f'Provided severity was "{severity_name}" but must be one of {", ".join(s.name for s in Severity)}.'
        )
