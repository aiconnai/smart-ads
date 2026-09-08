"""Explicit analyst proposals; these rules never assign a human decision."""

GROUPS = {
    'ledger-controller': (
        'Preserve the legacy lease, outbox, approval and recovery machinery; do not import it into the read gateway.',
        ['append-only recovery evidence', 'approval and idempotency binding', 'legacy state remains authoritative'],
        ['tests/autonomy/test_controller.py', 'tests/autonomy/test_ledger.py']),
    'disablement-governance': (
        'Retain the historical packet/template lifecycle under legacy governance; no credential action follows from decomposition.',
        ['immutable preparatory packet', 'separate human lifecycle checkpoints', 'no reuse of consumed authorization'],
        ['tests/test_service_account_disablement_authorization.py', 'tests/test_service_account_disablement_packet.py']),
    'codex-tooling': (
        'Rehome gates and scanners as repository tooling with their negative fixtures; exclude them from the distributable wheel.',
        ['trusted-base policy', 'complete range and payload coverage', 'no secrets in receipts', 'wheel excludes tooling'],
        ['tests/security/test_codex_gate.py']),
    'funnel': (
        'Defer the validator, schema and tests together. The read-gateway draft does not implement funnel publication semantics.',
        ['closed schemas and duplicate-key rejection', 'exact Decimal and time semantics', 'privacy and suppression gates'],
        ['tests/test_funnel_contract.py']),
    'google-canary': (
        'Defer the bounded canary, transport and fixtures to the Google phase; retain one-shot invocation and diagnostic limits.',
        ['explicit activation', 'consumed invocation cannot replay', 'bounded time/bytes/requests', 'sanitized output'],
        ['tests/operator/test_google_canary.py', 'tests/operator/test_google_canary_transport.py']),
    'pinna-write-plane': (
        'Defer the entire directory, including helpers, config and README, to the Write Plane. No mutation code is ported into read delivery.',
        ['human approval for writes', 'no inferred permission from helper purity', 'Customer Match data remains private'],
        []),
    'operator-conductor': (
        'Cleanly reimplement supplied-outcome orchestration; preserve validate/reduce/analyze ordering with collection owned by the host.',
        ['no collection inside conductor', 'canonical validated outcome', 'provider-agnostic injected intelligence'],
        ['tests/unit/test_conductor.py']),
    'security-filesystem': (
        'Reimplement the privacy invariant with synthetic fixtures; do not import the Pinna exporter or copy live output paths.',
        ['private file 0600 and directory 0700', 'reject symlink targets', 'retain opened directory under path swap', 'preserve existing parent mode'],
        []),
    'security-meta': (
        'Reimplement transport secrecy and allowlist tests with a fake read port. Legacy tests are evidence, not authorization for Graph I/O.',
        ['token only in header', 'allowlisted host before I/O', 'provider error bodies and exception chains stay value-silent'],
        []),
    'security-meta-mixed-write': (
        'This symbol also exercises POST. Preserve header/body sanitization as an invariant, but make read-gateway mutation attempts reject with zero I/O.',
        ['token stripped from query and payload', 'read path uses allowlisted host', 'POST path denied with zero provider calls'],
        []),
    'security-private-data': (
        'Port the output-exclusion invariant with synthetic file names; raw leads and exporter code do not enter the wheel.',
        ['sensitive outputs untracked and ignored', 'no raw lead data in docs or receipts'],
        []),
    'security-database-legacy': (
        'Keep the existing database diagnostic/document guard in legacy; it inspects files outside the 44-path source inventory.',
        ['diagnostics do not print environment values', 'static placeholders only', 'historical guide has no connection values'],
        ['tests/test_security_boundaries.py']),
    'security-history-legacy': (
        'Retain canonicalization helpers and historical authorization/disablement guards in legacy with their pinned documents and negative corpus.',
        ['exact historical digest', 'non-authorizing prose stays non-authorizing', 'value-silent metadata', 'encoded/confusable bypass rejection'],
        ['tests/test_security_boundaries.py']),
    'security-module-context': (
        'Retain mixed imports and historical constants as context. A clean target must select its own imports and fixtures; do not copy the module prefix.',
        ['no exporter/database imports in new tooling tests', 'historical constants remain bound to legacy guards'],
        ['tests/test_security_boundaries.py']),
    'source-whitespace': (
        'Account for these bytes without creating implementation. Whitespace has no independent destination or equivalence test.',
        ['source bytes remain covered'], []),
}

# Exact outer-definition names at the pinned baseline; unknown symbols reject.
SECURITY_GROUPS = {
    'test_private_output_normalization_does_not_exempt_arbitrary_root_paths': 'security-filesystem',
    'test_meta_request_uses_header_and_strips_query_tokens': 'security-meta-mixed-write',
    'test_meta_transport_rejects_non_allowlisted_host': 'security-meta',
    'test_meta_api_error_body_is_not_propagated': 'security-meta',
    'test_meta_transport_error_never_exposes_token': 'security-meta',
    'test_database_diagnostic_uri_uses_only_static_placeholders': 'security-database-legacy',
    'test_database_diagnostic_main_never_prints_supplied_values': 'security-database-legacy',
    'test_database_status_document_has_no_concrete_connection_values': 'security-database-legacy',
    '_canonicalize_historical_inventory_for_scan': 'security-history-legacy',
    '_metadata_field_values': 'security-history-legacy',
    '_assert_sanitized_scan_is_value_silent': 'security-history-legacy',
    '_assert_historical_inventory_semantics': 'security-history-legacy',
    '_assert_historical_inventory_is_value_silent': 'security-history-legacy',
    'test_historical_service_account_inventory_stays_value_silent': 'security-history-legacy',
    'test_historical_inventory_guard_rejects_sensitive_variants': 'security-history-legacy',
    'test_historical_inventory_guard_preserves_non_authorizing_history': 'security-history-legacy',
    'test_historical_inventory_guard_allows_harmless_prose_reflow': 'security-history-legacy',
    'test_historical_inventory_semantics_allow_harmless_latin_prose': 'security-history-legacy',
    'test_historical_inventory_semantics_allow_benign_pt_prose_across_line_break': 'security-history-legacy',
    'test_historical_inventory_semantics_reject_cross_line_pt_authorization': 'security-history-legacy',
    'test_historical_inventory_semantics_fail_closed_on_unreviewed_prose': 'security-history-legacy',
    '_assert_disablement_packet_semantics': 'security-history-legacy',
    '_assert_disablement_packet_is_value_silent': 'security-history-legacy',
    'test_disablement_packet_stays_value_silent_and_immutable': 'security-history-legacy',
    'test_disablement_packet_semantics_allow_safe_test_suffixes': 'security-history-legacy',
    'test_disablement_packet_raw_digest_rejects_rendering_sensitive_whitespace': 'security-history-legacy',
    'test_disablement_packet_guard_rejects_sensitive_variants': 'security-history-legacy',
    'test_disablement_packet_guard_is_immutable_against_edits': 'security-history-legacy',
    'test_lead_annex_outputs_are_covered_by_git_ignore': 'security-private-data',
    'test_meta_clients_use_shared_safe_transport': 'security-meta-mixed-write',
    'test_root_lead_generators_use_private_atomic_writer': 'security-private-data',
    'test_private_root_file_preserves_existing_parent_mode': 'security-filesystem',
    '_write_test_csv': 'security-filesystem',
    '_write_test_json': 'security-filesystem',
    '_write_test_html': 'security-filesystem',
    'test_sensitive_writers_enforce_private_modes_under_permissive_umask': 'security-filesystem',
    'test_sensitive_writers_reject_symlink_file_targets': 'security-filesystem',
    'test_sensitive_writers_reject_symlink_directories': 'security-filesystem',
    'test_sensitive_writer_retains_open_directory_when_path_is_swapped': 'security-filesystem',
}
