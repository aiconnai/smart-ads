# Revisão proposta das unidades de decomposição

Propostas do executor, não aprovação humana. Nenhum código legado foi executado.

Unidades: 122. Decisões humanas registradas: 0.
Digest da revisão: `sha256:881d66de1a2577cc35b90cd18fe4a2001514282076b6645227975fe5b139752b`.

O JSON contém IDs completos, seletores/digests, invariantes, testes planejados e vínculos locais.
A análise de arquivos inteiros combina a disposição do ADR com nomes/imports estáticos;
não é certificação de runtime nem revisão de todas as linhas desses sistemas.
Os testes citados são requisitos futuros ou referências legadas, não resultados executados.

## Grupos e justificativas

### codex-tooling — 7

Rehome gates and scanners as repository tooling with their negative fixtures; exclude them from the distributable wheel.

Invariantes: trusted-base policy; complete range and payload coverage; no secrets in receipts; wheel excludes tooling.

### disablement-governance — 5

Retain the historical packet/template lifecycle under legacy governance; no credential action follows from decomposition.

Invariantes: immutable preparatory packet; separate human lifecycle checkpoints; no reuse of consumed authorization.

### funnel — 3

Defer the validator, schema and tests together. The read-gateway draft does not implement funnel publication semantics.

Invariantes: closed schemas and duplicate-key rejection; exact Decimal and time semantics; privacy and suppression gates.

### google-canary — 5

Defer the bounded canary, transport and fixtures to the Google phase; retain one-shot invocation and diagnostic limits.

Invariantes: explicit activation; consumed invocation cannot replay; bounded time/bytes/requests; sanitized output.

### ledger-controller — 4

Preserve the legacy lease, outbox, approval and recovery machinery; do not import it into the read gateway.

Invariantes: append-only recovery evidence; approval and idempotency binding; legacy state remains authoritative.

### operator-conductor — 1

Cleanly reimplement supplied-outcome orchestration; preserve validate/reduce/analyze ordering with collection owned by the host.

Invariantes: no collection inside conductor; canonical validated outcome; provider-agnostic injected intelligence.

### pinna-write-plane — 18

Defer the entire directory, including helpers, config and README, to the Write Plane. No mutation code is ported into read delivery.

Invariantes: human approval for writes; no inferred permission from helper purity; Customer Match data remains private.

### security-database-legacy — 3

Keep the existing database diagnostic/document guard in legacy; it inspects files outside the 44-path source inventory.

Invariantes: diagnostics do not print environment values; static placeholders only; historical guide has no connection values.

### security-filesystem — 10

Reimplement the privacy invariant with synthetic fixtures; do not import the Pinna exporter or copy live output paths.

Invariantes: private file 0600 and directory 0700; reject symlink targets; retain opened directory under path swap; preserve existing parent mode.

### security-history-legacy — 24

Retain canonicalization helpers and historical authorization/disablement guards in legacy with their pinned documents and negative corpus.

Invariantes: exact historical digest; non-authorizing prose stays non-authorizing; value-silent metadata; encoded/confusable bypass rejection.

### security-meta — 3

Reimplement transport secrecy and allowlist tests with a fake read port. Legacy tests are evidence, not authorization for Graph I/O.

Invariantes: token only in header; allowlisted host before I/O; provider error bodies and exception chains stay value-silent.

### security-meta-mixed-write — 3

This symbol also exercises POST. Preserve header/body sanitization as an invariant, but make read-gateway mutation attempts reject with zero I/O.

Invariantes: token stripped from query and payload; read path uses allowlisted host; POST path denied with zero provider calls.

### security-module-context — 1

Retain mixed imports and historical constants as context. A clean target must select its own imports and fixtures; do not copy the module prefix.

Invariantes: no exporter/database imports in new tooling tests; historical constants remain bound to legacy guards.

### security-private-data — 3

Port the output-exclusion invariant with synthetic file names; raw leads and exporter code do not enter the wheel.

Invariantes: sensitive outputs untracked and ignored; no raw lead data in docs or receipts.

### source-whitespace — 32

Account for these bytes without creating implementation. Whitespace has no independent destination or equivalence test.

Invariantes: source bytes remain covered.

## `DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_AUTHORIZATION.md`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `2197d697fdfb` | 1–458 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_AUTHORIZATION.md` |
## `DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_DECISION_PACKET.md`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `66a900c77b8b` | 1–198 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_DECISION_PACKET.md` |
## `config/analytics/funnel_contract_v1.yaml`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `a067449b79cd` | 1–1491 | `whole_file` | `defer_to_funnel_integration` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `config/operator/service_account_authorization_template.sha256`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `d1c77feba6f3` | 1–1 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:config/operator/service_account_authorization_template.sha256` |
## `docs/harness/bin/build_codex_manifest.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `8f4e89e5dc50` | 1–303 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/build_codex_manifest.py` |
## `docs/harness/bin/build_trusted_policy.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `ede77dccd02e` | 1–80 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/build_trusted_policy.py` |
## `docs/harness/bin/codex-gate.sh`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `5eccfa6d43b7` | 1–746 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/codex-gate.sh` |
## `docs/harness/bin/scan_codex_payload.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `02accf7cf3ad` | 1–2008 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/scan_codex_payload.py` |
## `docs/harness/bin/validate_codex_range.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `0b3765e424d1` | 1–170 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/validate_codex_range.py` |
## `docs/harness/bin/write_codex_receipt.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `fc9ca01d5057` | 1–343 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tooling/governance/write_codex_receipt.py` |
## `scripts/analytics/validate_funnel_contract.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `b925c8f1d292` | 1–2786 | `whole_file` | `defer_to_funnel_integration` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/autonomy/controller.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `172db713301d` | 1–964 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:scripts/autonomy/controller.py` |
## `scripts/autonomy/ledger.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `c95da61bc9dc` | 1–4979 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:scripts/autonomy/ledger.py` |
## `scripts/google_ads/pinna5109/README.md`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `6608c1151dc3` | 1–185 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/__init__.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `5920c25a0e0f` | 1–1 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/add_entre_variants.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `bdef306b1f43` | 1–288 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/apply_structure.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `f36f917cc4d5` | 1–554 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/build_ultra_premium_list.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `643c9126cab6` | 1–196 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/cleanup_itaim_sdi_tellus.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `f31b4540db74` | 1–361 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/config.yaml`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `60a0ffe9fd8c` | 1–181 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/create_brand_defense.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `ef2239c50481` | 1–326 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/create_campaign.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `570856ae99d2` | 1–876 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/create_intl_campaign.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `4bc7c423999b` | 1–726 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/enable_ad_groups.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `12d71ecfde70` | 1–131 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/expand_ads_and_keywords.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `488543df4f99` | 1–465 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/format_cm_google.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `ee66ba0dccd4` | 1–128 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/generate_cm_upload_csvs.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `1935f19c2d83` | 1–116 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/restore_itaim_bibi.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `3ced4aaa9c24` | 1–276 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/resume_pinna.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `62bec0185f5c` | 1–264 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/update_final_urls.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `5c8115d5a4b5` | 1–198 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/google_ads/pinna5109/upload_customer_match.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `286cad21fbee` | 1–349 | `whole_file` | `defer_to_write_plane` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/operator/conductor.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `90743fa25fa0` | 1–40 | `whole_file` | `reimplement_clean` | `aiconnai/smart-ads:src/smart_ads/application/conductor.py` |
## `scripts/operator/google_canary.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `7aafe2d6c58e` | 1–2125 | `whole_file` | `defer_to_google_phase` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `scripts/operator/google_canary_transport.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `bd1c1e8cde76` | 1–379 | `whole_file` | `defer_to_google_phase` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/autonomy/test_controller.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `4dedf83968f8` | 1–3459 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/autonomy/test_controller.py` |
## `tests/autonomy/test_ledger.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `381b841a3e32` | 1–662 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/autonomy/test_ledger.py` |
## `tests/operator/fixtures/google_canary/google_shape_r1_sanitized.json`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `cd824ac60a01` | 1–30 | `whole_file` | `defer_to_google_phase` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/operator/test_google_canary.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `e4424b93a841` | 1–3148 | `whole_file` | `defer_to_google_phase` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/operator/test_google_canary_transport.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `71aca1e94fc1` | 1–355 | `whole_file` | `defer_to_google_phase` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/test_codex_gate.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `1bf9e52b5ebd` | 1–2806 | `whole_file` | `repository_tooling` | `aiconnai/smart-ads:tests/security/test_codex_gate.py` |
## `tests/test_funnel_contract.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `05d808f624ba` | 1–1677 | `whole_file` | `defer_to_funnel_integration` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/test_security_boundaries.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `147941021e03` | 1–72 | `text_region` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `083f19088a77` | 73–76 | `test_private_output_normalization_does_not_exempt_arbitrary_root_paths` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_private_output_normalization_does_not_exempt_arbitrary_root_paths.py` |
| `b2942b5a90e4` | 76–78 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `cee8feaabfc4` | 79–131 | `test_meta_request_uses_header_and_strips_query_tokens` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_request_uses_header_and_strips_query_tokens.py` |
| `5e60b59dcda7` | 131–133 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `e33a8062aab5` | 134–140 | `test_meta_transport_rejects_non_allowlisted_host` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_transport_rejects_non_allowlisted_host.py` |
| `64c16adc103c` | 140–142 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `d67a3683e061` | 143–165 | `test_meta_api_error_body_is_not_propagated` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_api_error_body_is_not_propagated.py` |
| `4bb51060237c` | 165–167 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `ce5614943575` | 168–185 | `test_meta_transport_error_never_exposes_token` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_transport_error_never_exposes_token.py` |
| `5bd41113c385` | 185–187 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `025033da64fd` | 188–194 | `test_database_diagnostic_uri_uses_only_static_placeholders` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `e2aadd60b2f2` | 194–196 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `1bbd939d470c` | 197–226 | `test_database_diagnostic_main_never_prints_supplied_values` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `c2b22e049754` | 226–228 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `23173d6a50a1` | 229–241 | `test_database_status_document_has_no_concrete_connection_values` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `a0abfe743e35` | 241–243 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `df2f7f161f15` | 244–301 | `_canonicalize_historical_inventory_for_scan` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `6276af27d468` | 301–303 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `8cc74e3bbfd3` | 304–322 | `_metadata_field_values` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `666e030dcee0` | 322–324 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `202180729825` | 325–486 | `_assert_sanitized_scan_is_value_silent` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `3398a9983c03` | 486–487 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `e23f7c3d1e78` | 488–600 | `_assert_historical_inventory_semantics` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `ce691bd0be55` | 600–602 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `c2dec0d82cd0` | 603–609 | `_assert_historical_inventory_is_value_silent` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `011fb11cf064` | 609–611 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `ed43be651297` | 612–617 | `test_historical_service_account_inventory_stays_value_silent` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `6ac25efc837c` | 617–785 | `decorador de test_historical_inventory_guard_rejects_sensitive_variants` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `c6e8a4700a02` | 786–796 | `test_historical_inventory_guard_rejects_sensitive_variants` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `babb42b4dc44` | 796–849 | `decorador de test_historical_inventory_guard_preserves_non_authorizing_history` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `6466da9db71f` | 850–860 | `test_historical_inventory_guard_preserves_non_authorizing_history` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `41dd4ed4bfea` | 860–862 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `4782a351a779` | 863–874 | `test_historical_inventory_guard_allows_harmless_prose_reflow` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `1e73f0bbe7bb` | 874–876 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `0f9d0766721f` | 877–884 | `test_historical_inventory_semantics_allow_harmless_latin_prose` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `f452b406b9b7` | 884–886 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `abb514deae42` | 887–951 | `test_historical_inventory_semantics_allow_benign_pt_prose_across_line_break` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `6aa36032cf58` | 951–953 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `f417baf4ad6d` | 954–963 | `test_historical_inventory_semantics_reject_cross_line_pt_authorization` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `8d72b35d61ee` | 963–965 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `9edbe204097b` | 966–974 | `test_historical_inventory_semantics_fail_closed_on_unreviewed_prose` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `0f95dc2eb5cb` | 974–976 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `7c054699202e` | 977–1083 | `_assert_disablement_packet_semantics` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `d3468a1faad2` | 1083–1085 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `3addbd04b899` | 1086–1091 | `_assert_disablement_packet_is_value_silent` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `613dea5799a1` | 1091–1093 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `0b7eb74251eb` | 1094–1102 | `test_disablement_packet_stays_value_silent_and_immutable` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `eae1284b5022` | 1102–1104 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `967f36d1c488` | 1105–1113 | `test_disablement_packet_semantics_allow_safe_test_suffixes` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `1d2cbef7a5c4` | 1113–1115 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `1bec45231fb8` | 1116–1131 | `test_disablement_packet_raw_digest_rejects_rendering_sensitive_whitespace` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `f70df169fd2a` | 1131–1183 | `decorador de test_disablement_packet_guard_rejects_sensitive_variants` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `569c874696f3` | 1184–1194 | `test_disablement_packet_guard_rejects_sensitive_variants` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `a15613e4dccb` | 1194–1241 | `decorador de test_disablement_packet_guard_is_immutable_against_edits` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `eefc611373e3` | 1242–1252 | `test_disablement_packet_guard_is_immutable_against_edits` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py` |
| `0c82fb8b45b1` | 1252–1254 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `0a5d9234fd5f` | 1255–1306 | `test_lead_annex_outputs_are_covered_by_git_ignore` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_lead_annex_outputs_are_covered_by_git_ignore.py` |
| `0514e32b433d` | 1306–1319 | `decorador de test_meta_clients_use_shared_safe_transport` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_clients_use_shared_safe_transport.py` |
| `78254dc02332` | 1320–1323 | `test_meta_clients_use_shared_safe_transport` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_meta_clients_use_shared_safe_transport.py` |
| `ab85463c3b80` | 1323–1334 | `decorador de test_root_lead_generators_use_private_atomic_writer` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_root_lead_generators_use_private_atomic_writer.py` |
| `e83a9a3e83e1` | 1335–1337 | `test_root_lead_generators_use_private_atomic_writer` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_root_lead_generators_use_private_atomic_writer.py` |
| `894f430355b6` | 1337–1339 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `a133e2ecdd04` | 1340–1350 | `test_private_root_file_preserves_existing_parent_mode` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_private_root_file_preserves_existing_parent_mode.py` |
| `0ceb3bb34026` | 1350–1352 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `29ffe00b4279` | 1353–1354 | `_write_test_csv` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/write_test_csv.py` |
| `8404f2914ed7` | 1354–1356 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `d3156a2641e8` | 1357–1358 | `_write_test_json` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/write_test_json.py` |
| `ce68de4d719f` | 1358–1360 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `878987e345ed` | 1361–1362 | `_write_test_html` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/write_test_html.py` |
| `fc7afa526571` | 1362–1364 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `3645fa93566d` | 1365–1385 | `test_sensitive_writers_enforce_private_modes_under_permissive_umask` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writers_enforce_private_modes_under_permissive_umask.py` |
| `9ea847869a6b` | 1385–1395 | `decorador de test_sensitive_writers_reject_symlink_file_targets` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writers_reject_symlink_file_targets.py` |
| `5f8588a246b0` | 1396–1412 | `test_sensitive_writers_reject_symlink_file_targets` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writers_reject_symlink_file_targets.py` |
| `ea64c851099f` | 1412–1414 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `c6805b0d23bd` | 1415–1424 | `test_sensitive_writers_reject_symlink_directories` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writers_reject_symlink_directories.py` |
| `cd475fb596ed` | 1424–1426 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
| `6666e1ee5dd0` | 1427–1467 | `test_sensitive_writer_retains_open_directory_when_path_is_swapped` | `split_by_invariant` | `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writer_retains_open_directory_when_path_is_swapped.py` |
| `7181d6f04ea5` | 1467–1467 | `text_region` | `reference_only` | `mbras-tech/mbras-campaigns (sem implementação)` |
## `tests/test_service_account_disablement_authorization.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `90892f8bfefd` | 1–1920 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_service_account_disablement_authorization.py` |
## `tests/test_service_account_disablement_packet.py`

| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |
|---|---|---|---|---|
| `3048a1809361` | 1–94 | `whole_file` | `legacy_governance_only` | `mbras-tech/mbras-campaigns:tests/test_service_account_disablement_packet.py` |

## Destinos compartilhados — materialização pendente

Não renomear artificialmente arquivos legados nem soltar decoradores de suas funções.
O draft atual recusa esses grupos; o contrato final de seletores/assembly deve resolvê-los.

- `aiconnai/smart-ads:tests/security/decomposed/test_meta_clients_use_shared_safe_transport.py`: 2 unidades.
- `aiconnai/smart-ads:tests/security/decomposed/test_root_lead_generators_use_private_atomic_writer.py`: 2 unidades.
- `aiconnai/smart-ads:tests/security/decomposed/test_sensitive_writers_reject_symlink_file_targets.py`: 2 unidades.
- `mbras-tech/mbras-campaigns:tests/test_security_boundaries.py`: 28 unidades.
