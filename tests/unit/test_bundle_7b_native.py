"""7B ``native_request_projection/v1`` (closed, redacted) and its injected check."""
from __future__ import annotations

from collections.abc import Callable
import copy
import dataclasses
import hashlib
from typing import Any

import pytest

from smart_ads.contracts.jcs import p1_content_digest
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import CanonicalQueryContract
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import Bundle7BDefectError
from tests.unit._bundle_7b_builders import (
    CLICKS,
    DAY,
    KEY_ID,
    REF_A,
    REF_B,
    SPEND,
    canonical_query,
    code_of,
    native_dict,
    oracle_jcs,
    registry_loc,
    sha,
    signature,
)

NATIVE_KEYS = (
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
ALGORITHM_DIGEST = sha("a")


def native_defect(data: object) -> str:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(data)
    return code_of(excinfo)


def test_native_projection_round_trips_with_only_the_adr_members() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    assert tuple(projection.to_dict()) == NATIVE_KEYS
    assert projection.to_dict() == native_dict()
    expected = "sha256:" + hashlib.sha256(oracle_jcs(native_dict())).hexdigest()
    assert projection.native_request_digest == expected


@pytest.mark.parametrize(
    "extra",
    ["headers", "access_token", "authorization", "raw_response", "provider_payload",
     "time_increment", "limit", "url", "query"],
)
def test_native_projection_rejects_any_extra_member(extra: str) -> None:
    assert native_defect(native_dict(**{extra: "x"})) == "closed_member_set"


@pytest.mark.parametrize("missing", NATIVE_KEYS)
def test_native_projection_rejects_any_missing_member(missing: str) -> None:
    data = native_dict()
    del data[missing]
    assert native_defect(data) == "closed_member_set"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://graph.facebook.com/v21.0/insights",
        "//graph.facebook.com/v21.0/insights",
        "/v21.0/insights?fields=spend",
        "/v21.0/insights?access_token=secret",
        "/v21.0/insights#fragment",
        "/user:secret@graph.facebook.com/insights",
        "/v21.0/act_1234567890/insights",
        "/v21.0/1234567890/insights",
        "/v21.0/insights/",
        "v21.0/insights",
        "/",
        "",
    ],
)
def test_native_projection_rejects_urls_authority_query_and_raw_ids(endpoint: str) -> None:
    assert native_defect(native_dict(endpoint=endpoint)) == "native_projection_forbidden_content"


@pytest.mark.parametrize("raw_ref", ["act_1234567890", "1234567890", "campaign:123"])
def test_native_projection_rejects_raw_provider_identifiers(raw_ref: str) -> None:
    assert native_defect(native_dict(resource_refs=[raw_ref])) == (
        "native_projection_forbidden_content"
    )


@pytest.mark.parametrize(
    ("member", "value", "code"),
    [
        ("metrics", ["impressions", "clicks", "spend"], "wrong_order"),
        ("metrics", ["clicks", "clicks", "spend"], "duplicate_identity"),
        ("resource_refs", [REF_B, REF_A], "wrong_order"),
        ("breakdowns", ["region", "age"], "wrong_order"),
        ("metrics", [], "malformed_member"),
        ("resource_refs", [], "malformed_member"),
        ("metrics", "clicks", "malformed_member"),
        ("metrics", ["Clicks"], "malformed_member"),
        ("http_method", "PUT", "malformed_member"),
        ("endpoint_version_ref", "version:v21.0", "malformed_member"),
        ("currency", "brl", "malformed_member"),
        ("date_range", {"start_date": DAY}, "malformed_member"),
        ("resource_level", "Campaign 1", "malformed_member"),
        ("pagination", "page=2", "malformed_member"),
        ("endpoint", b"/v21.0/insights", "malformed_member"),
        ("attribution_omission_state", "present", "fixed_member_mismatch"),
        ("$schema", "smart_ads/native_request/v1", "fixed_member_mismatch"),
    ],
)
def test_native_projection_member_grammar(member: str, value: object, code: str) -> None:
    assert native_defect(native_dict(**{member: value})) == code


OPAQUE_REF = "opaque-driver-contract:" + sha("3")


@pytest.mark.parametrize(
    ("endpoint", "version_ref", "code"),
    [
        # Reference: every version segment must equal the Gate-3 version in the ref.
        ("/v99.0/insights", "api-version:v21.0", "native_version_mismatch"),
        ("/v21.0/insights/v22", "api-version:v21.0", "native_version_mismatch"),
        ("/v21/insights", "api-version:v21.0", "native_version_mismatch"),
        # Candidate: Pipeboard is version-opaque, so no version segment at all.
        ("/v21.0/insights", OPAQUE_REF, "native_version_mismatch"),
        ("/mcp/v1/tools", OPAQUE_REF, "native_version_mismatch"),
        # The standalone opaque identity is exactly a sha256 digest.
        ("/mcp/tools/get_insights", "opaque-driver-contract:pipeboard-v1", "malformed_member"),
        ("/mcp/tools/get_insights", "opaque-driver-contract:sha256:ABC", "malformed_member"),
        ("/mcp/tools/get_insights", "opaque-driver-contract:sha256:" + "A" * 64,
         "malformed_member"),
        ("/mcp/tools/get_insights", "opaque-driver-contract:sha256:" + "a" * 63,
         "malformed_member"),
        ("/mcp/tools/get_insights", "opaque-driver-contract:sha256:" + "a" * 65,
         "malformed_member"),
    ],
)
def test_native_endpoint_version_must_match_its_version_identity(
    endpoint: str, version_ref: str, code: str
) -> None:
    data = native_dict(endpoint=endpoint, endpoint_version_ref=version_ref)
    assert native_defect(data) == code


@pytest.mark.parametrize(
    ("endpoint", "version_ref"),
    [
        ("/v21.0/insights", "api-version:v21.0"),
        ("/insights", "api-version:v21.0"),
        ("/mcp/tools/get_insights", OPAQUE_REF),
    ],
)
def test_native_endpoint_version_accepts_matching_identities(
    endpoint: str, version_ref: str
) -> None:
    data = native_dict(endpoint=endpoint, endpoint_version_ref=version_ref)
    assert b7.NativeRequestProjection.from_dict(data).endpoint == endpoint


@pytest.mark.parametrize("endpoint", ["/insights", "/v21.0/insights"])
@pytest.mark.parametrize(
    ("suffix", "secret"),
    [
        ("act_1234567890", "act_1234567890"),
        ("Bearer:EAAsecretToken123", "EAAsecretToken123"),
        ("21.0", "21.0"),
        ("V21.0", "V21.0"),
        ("v21.", "v21."),
    ],
)
def test_native_api_version_enforces_closed_grammar_without_echoing_input(
    endpoint: str, suffix: str, secret: str
) -> None:
    data = native_dict(endpoint=endpoint, endpoint_version_ref=f"api-version:{suffix}")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(data)
    assert code_of(excinfo) == "malformed_member"
    assert secret not in str(excinfo.value)


def test_native_version_mismatch_never_echoes_the_version_body() -> None:
    data = native_dict(endpoint="/v99.0/insights", endpoint_version_ref="api-version:v21.0")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(data)
    assert code_of(excinfo) == "native_version_mismatch"
    assert "v21.0" not in str(excinfo.value)
    assert "v99.0" not in str(excinfo.value)


@pytest.mark.parametrize("name", ["resource_refs", "metrics", "breakdowns"])
def test_native_projection_sequence_members_must_be_tuples(name: str) -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    assert hash(projection) == hash(b7.NativeRequestProjection.from_dict(native_dict()))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        dataclasses.replace(projection, **{name: list(getattr(projection, name))})
    assert code_of(excinfo) == "malformed_member"


def test_native_projection_rejects_non_mapping_input() -> None:
    for bad in ("x", None, {1: "x"}):
        assert native_defect(bad) == "malformed_member"


def test_native_projection_accepts_a_p1_integrity_block_and_checks_it() -> None:
    unsigned = native_dict(
        integrity={"key_id": KEY_ID, "key_registry_snapshot_locator": registry_loc().to_dict()}
    )
    projection = b7.NativeRequestProjection.from_dict(unsigned)
    digest = p1_content_digest(projection.to_dict())
    signed = copy.deepcopy(unsigned)
    signed["integrity"].update(content_digest=digest, signature_base64=signature())
    assert b7.NativeRequestProjection.from_dict(signed).to_dict() == signed
    assert b7.NativeRequestProjection.from_dict(signed, require_signed=True).to_dict() == signed
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(native_dict(), require_signed=True)
    assert code_of(excinfo) == "closed_member_set"
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(unsigned, require_signed=True)
    assert code_of(excinfo) == "malformed_member"
    for bad_flag in ("yes", 1, None):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            b7.NativeRequestProjection.from_dict(
                signed, require_signed=bad_flag  # type: ignore[arg-type]
            )
        assert code_of(excinfo) == "malformed_argument"
    signed["integrity"]["content_digest"] = sha("0")
    assert native_defect(signed) == "integrity_digest_mismatch"


def identity_algorithm(
    seen: list[tuple[b7.NativeRequestProjection, str]] | None = None,
) -> Callable[[b7.NativeRequestProjection, str], CanonicalQueryContract]:
    def run(projection: b7.NativeRequestProjection, algorithm_digest: str) -> CanonicalQueryContract:
        if seen is not None:
            seen.append((projection, algorithm_digest))
        return canonical_query()

    return run


def test_native_check_recomputes_the_digest_and_runs_the_pinned_algorithm() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    seen: list[tuple[b7.NativeRequestProjection, str]] = []
    b7.check_native_request(
        projection,
        native_request_digest=projection.native_request_digest,
        canonical_query=canonical_query(),
        algorithm_digest=ALGORITHM_DIGEST,
        project_native_request=identity_algorithm(seen),
    )
    assert seen == [(projection, ALGORITHM_DIGEST)]


def test_native_check_rejects_a_divergent_native_digest() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(
            projection,
            native_request_digest=sha("0"),
            canonical_query=canonical_query(),
            algorithm_digest=ALGORITHM_DIGEST,
            project_native_request=identity_algorithm(),
        )
    assert code_of(excinfo) == "native_request_digest_mismatch"


def _raising(projection: b7.NativeRequestProjection, digest: str) -> CanonicalQueryContract:
    raise ClosedValidationError("extra default-valued native parameter")


@pytest.mark.parametrize(
    "algorithm",
    [
        lambda p, d: dataclasses.replace(canonical_query(), metric_semantic_refs=(CLICKS, SPEND)),
        lambda p, d: dataclasses.replace(canonical_query(), tzdb_version="2026b"),
        lambda p, d: canonical_query().to_dict(),
        lambda p, d: None,
        _raising,
    ],
)
def test_native_check_requires_byte_identical_canonical_projection(
    algorithm: Callable[[b7.NativeRequestProjection, str], Any],
) -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(
            projection,
            native_request_digest=projection.native_request_digest,
            canonical_query=canonical_query(),
            algorithm_digest=ALGORITHM_DIGEST,
            project_native_request=algorithm,
        )
    assert code_of(excinfo) == "native_projection_mismatch"


def test_native_check_rejects_wrongly_typed_arguments() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    good: dict[str, Any] = {
        "native_request_digest": projection.native_request_digest,
        "canonical_query": canonical_query(),
        "algorithm_digest": ALGORITHM_DIGEST,
        "project_native_request": identity_algorithm(),
    }
    for name, bad in (
        ("canonical_query", canonical_query().to_dict()),
        ("algorithm_digest", "sha256:X"),
        ("project_native_request", "not-callable"),
        ("native_request_digest", None),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            b7.check_native_request(projection, **dict(good, **{name: bad}))
        assert code_of(excinfo) in {"malformed_argument", "malformed_member"}
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(native_dict(), **good)  # type: ignore[arg-type]
    assert code_of(excinfo) == "malformed_argument"


class _AlwaysEq:
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


def _tampered_projected(
    field: str, value: object, *, delete: bool = False
) -> CanonicalQueryContract:
    query = canonical_query()
    if delete:
        object.__delattr__(query, field)
    else:
        object.__setattr__(query, field, value)
    return query


class _SubclassedQuery(CanonicalQueryContract):
    def to_dict(self) -> dict[str, Any]:
        raise ClosedValidationError("broken subclass to_dict")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: _tampered_projected("tzdb_version", 1.5),
        lambda: _tampered_projected("resource_level", _AlwaysEq()),
        lambda: _tampered_projected("date_range", None),
        lambda: _tampered_projected("tzdb_version", None, delete=True),
        lambda: _SubclassedQuery(**{
            k: v for k, v in canonical_query().__dict__.items()
        }) if hasattr(canonical_query(), "__dict__") else _SubclassedQuery(
            **{f.name: getattr(canonical_query(), f.name)
               for f in dataclasses.fields(CanonicalQueryContract)}
        ),
    ],
)
def test_native_check_reparses_callback_return_value_under_coded_defect(
    factory: Callable[[], CanonicalQueryContract],
) -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(
            projection,
            native_request_digest=projection.native_request_digest,
            canonical_query=canonical_query(),
            algorithm_digest=ALGORITHM_DIGEST,
            project_native_request=lambda p, d: factory(),
        )
    assert code_of(excinfo) == "native_projection_mismatch"
