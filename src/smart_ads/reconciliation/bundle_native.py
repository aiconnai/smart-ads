"""Closed, redacted ``native_request_projection/v1`` and its injected check (ADR-0001 5.4).

ADR L1211-1220 lists the projection's content only as concepts; the member
names below are a choice the ADR does not fix. ``native_request_digest`` is
sha256 over the RFC 8785 bytes of the complete ``to_dict()`` (including
``integrity`` when present), also a choice the ADR does not fix beyond "from
RFC 8785 bytes". The native-to-canonical algorithm itself is injected.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import P1Integrity, jcs_sha256
from smart_ads.contracts.schemas import CanonicalQueryContract, DateRange
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_mapping,
    validate_currency_iso4217,
    validate_resource_ref,
)
from smart_ads.reconciliation.bundle_common import (
    NATIVE_REQUEST_PROJECTION_SCHEMA,
    Bundle7BDefectError,
    check_integrity,
    guard,
    hyphen_ref,
    parse_integrity,
    query_bytes,
    require_callable,
    require_member,
    require_strictly_ascending,
    require_type,
    sha256_member,
)

_NATIVE_ARRAY_MEMBERS: Final[tuple[str, ...]] = ("resource_refs", "metrics", "breakdowns")
_HTTP_METHODS: Final[frozenset[str]] = frozenset({"GET", "POST"})
_ENDPOINT_VERSION_PREFIXES: Final[frozenset[str]] = frozenset(
    {"api-version", "opaque-driver-contract"}
)
_ATTRIBUTION_OMITTED: Final[str] = "omitted"
# Path only: no scheme, authority, userinfo, query or fragment. A segment is either an
# API version (`v21.0`) or a lowercase name without digits, so raw numeric provider
# identifiers (`act_123`, `1234`) cannot appear in the endpoint.
_ENDPOINT_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(?:/(?:v[0-9]+(?:\.[0-9]+)*|[a-z][a-z_-]*))+\Z"
)
_NATIVE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z_]*\Z")


def _native_name(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _NATIVE_NAME_RE.fullmatch(value) is None:
        raise Bundle7BDefectError("malformed_member", f"{label}: invalid native name")
    return value


def _native_name_checker(label: str) -> Callable[[object], str]:
    def check(value: object) -> str:
        return _native_name(value, label=label)

    return check


def _sorted_native_array(
    values: object, *, label: str, check: Callable[[object], str], allow_empty: bool
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected an array")
    if not values and not allow_empty:
        raise Bundle7BDefectError("malformed_member", f"{label}: must not be empty")
    checked = tuple(check(value) for value in values)
    require_strictly_ascending([value.encode("utf-8") for value in checked], label=label)
    return checked


def _canonical_resource_ref(value: object) -> str:
    label = "native_request_projection.resource_refs"
    try:
        return validate_resource_ref(value, field_name=label)
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(
            "native_projection_forbidden_content",
            f"{label}: only tenant-scoped resource refs are allowed",
        ) from exc


def _check_endpoint(endpoint: object) -> None:
    label = "native_request_projection.endpoint"
    if not isinstance(endpoint, str):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected str")
    if _ENDPOINT_PATH_RE.fullmatch(endpoint) is None:
        raise Bundle7BDefectError(
            "native_projection_forbidden_content",
            f"{label}: only an authority-free, query-free path without raw ids is allowed",
        )


def _json_array(value: object, *, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected a JSON array")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class NativeRequestProjection:
    """Closed redacted ``native_request_projection/v1`` (``additionalProperties: false``)."""

    SCHEMA: ClassVar[str] = NATIVE_REQUEST_PROJECTION_SCHEMA
    CORE_KEYS: ClassVar[tuple[str, ...]] = (
        "$schema",
        "endpoint",
        "http_method",
        "endpoint_version_ref",
        "resource_refs",
        "date_range",
        "resource_level",
        "metrics",
        "breakdowns",
        "pagination",
        "currency",
        "attribution_omission_state",
    )

    endpoint: str
    http_method: str
    endpoint_version_ref: str
    resource_refs: tuple[str, ...]
    date_range: DateRange
    resource_level: str
    metrics: tuple[str, ...]
    breakdowns: tuple[str, ...]
    pagination: str
    currency: str
    attribution_omission_state: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "native_request_projection"
        _check_endpoint(self.endpoint)
        if not isinstance(self.http_method, str) or self.http_method not in _HTTP_METHODS:
            raise Bundle7BDefectError(
                "malformed_member", f"{label}.http_method: expected GET or POST"
            )
        hyphen_ref(
            self.endpoint_version_ref,
            prefixes=_ENDPOINT_VERSION_PREFIXES,
            label=f"{label}.endpoint_version_ref",
        )
        self._check_arrays(label)
        require_member(self.date_range, DateRange, label=f"{label}.date_range")
        _native_name(self.resource_level, label=f"{label}.resource_level")
        _native_name(self.pagination, label=f"{label}.pagination")
        field = f"{label}.currency"
        guard(
            "malformed_member",
            field,
            lambda: validate_currency_iso4217(self.currency, field_name=field),
        )
        if self.attribution_omission_state != _ATTRIBUTION_OMITTED:
            raise Bundle7BDefectError(
                "fixed_member_mismatch", f"{label}.attribution_omission_state: must be 'omitted'"
            )
        check_integrity(self.integrity, self.to_dict, label=label)

    def _check_arrays(self, label: str) -> None:
        _sorted_native_array(
            self.resource_refs,
            label=f"{label}.resource_refs",
            check=_canonical_resource_ref,
            allow_empty=False,
        )
        for name, allow_empty in (("metrics", False), ("breakdowns", True)):
            _sorted_native_array(
                getattr(self, name),
                label=f"{label}.{name}",
                check=_native_name_checker(f"{label}.{name}"),
                allow_empty=allow_empty,
            )

    @property
    def native_request_digest(self) -> str:
        """``sha256:`` over the RFC 8785 bytes of the complete projection."""
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "endpoint": self.endpoint,
            "http_method": self.http_method,
            "endpoint_version_ref": self.endpoint_version_ref,
            "resource_refs": list(self.resource_refs),
            "date_range": self.date_range.to_dict(),
            "resource_level": self.resource_level,
            "metrics": list(self.metrics),
            "breakdowns": list(self.breakdowns),
            "pagination": self.pagination,
            "currency": self.currency,
            "attribution_omission_state": self.attribution_omission_state,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object) -> NativeRequestProjection:
        label = "native_request_projection"
        mapping = guard("malformed_member", label, lambda: require_mapping(data, label=label))
        keys = set(cls.CORE_KEYS) | ({"integrity"} if "integrity" in mapping else set())
        actual = set(mapping)
        if actual != keys:
            raise Bundle7BDefectError(
                "native_projection_not_closed",
                f"{label}: missing={sorted(keys - actual)} extra={sorted(actual - keys)}",
            )
        if mapping["$schema"] != cls.SCHEMA:
            raise Bundle7BDefectError(
                "fixed_member_mismatch", f"{label}.$schema: expected {cls.SCHEMA!r}"
            )
        arrays = {
            name: _json_array(mapping[name], label=f"{label}.{name}")
            for name in _NATIVE_ARRAY_MEMBERS
        }
        scalars = {
            name: mapping[name]
            for name in set(cls.CORE_KEYS) - {"$schema", "date_range", *_NATIVE_ARRAY_MEMBERS}
        }
        date_range = guard(
            "malformed_member",
            f"{label}.date_range",
            lambda: DateRange.from_dict(mapping["date_range"]),
        )
        return cls(
            date_range=date_range,
            integrity=parse_integrity(mapping, label=label),
            **arrays,
            **scalars,
        )


NativeToCanonicalAlgorithm = Callable[[NativeRequestProjection, str], CanonicalQueryContract]


def check_native_request(
    projection: NativeRequestProjection,
    *,
    native_request_digest: str,
    canonical_query: CanonicalQueryContract,
    algorithm_digest: str,
    project_native_request: NativeToCanonicalAlgorithm,
) -> None:
    """Recompute ``native_request_digest`` and run the injected, digest-pinned projection.

    The resulting complete canonical projection must equal ``canonical_query``
    byte-for-byte; any other result (including a rejection by the algorithm of
    an extra or default-valued native parameter) fails 7B.
    """
    require_type(projection, NativeRequestProjection, label="native_request_projection")
    require_type(canonical_query, CanonicalQueryContract, label="canonical_query")
    sha256_member(native_request_digest, label="native_request_digest")
    sha256_member(algorithm_digest, label="native_to_canonical_projection_algorithm_digest")
    require_callable(project_native_request, label="project_native_request")
    if projection.native_request_digest != native_request_digest:
        raise Bundle7BDefectError(
            "native_request_digest_mismatch", "native_request_digest differs"
        )
    try:
        projected = project_native_request(projection, algorithm_digest)
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(
            "native_projection_mismatch", f"algorithm rejected: {exc}"
        ) from exc
    if not isinstance(projected, CanonicalQueryContract) or query_bytes(
        projected
    ) != query_bytes(canonical_query):
        raise Bundle7BDefectError(
            "native_projection_mismatch", "projected canonical query is not byte-identical"
        )
