# Caminho do Gate 2 ao Gate 3

> Estado em 2026-09-04. Gate 2 **GRANTED** em `82e98f7`.
> Este documento mapeia o que separa o Gate 2 do Gate 3, derivado do fluxo normativo
> do ADR-0001 (linhas 2336-2365) e das seções 5.3, 9 e 12.

## Por que o Gate 3 não é o próximo passo

O Gate 3 seleciona a versão exata da API da Meta **no momento da ativação**. O mapa de
fechamento do ADR é explícito (C05):

> *Gate 3 version is an unresolved exact activation-time selection, never a static
> constant.*

Três bloqueios concretos, hoje:

1. **Chamadas ao vivo.** `supported_versions_observed_digest` vem de evidência
   recomputada contra a API real. A certificação 7B exige duas chamadas independentes
   (candidata via Pipeboard, referência via cliente oficial Meta), cada uma com
   autorização humana e reserva próprias.
2. **Janela de 900 segundos.** `valid_until_utc` deve ser exatamente
   `revalidated_at_utc + 900s`, com `maximum_clock_uncertainty_ms: 1000` e
   `maximum_provider_dispatch_deadline_seconds: 60`. A revalidação ocorre imediatamente
   antes da reserva e novamente após materializar credenciais, antes da construção do
   socket. Nada disso é preparável offline.
3. **Digests de código que ainda não existe.** O `certification_fingerprint` inclui
   `parser_code_digest`, `adapter_code_digest`, `mapping_rules_digest`,
   `schema_bundle_digest` e `resource_mapping_contract_digest` — o parser, o adapter e o
   schema bundle são justamente o produto de PR1-PR5.

## O caminho, etapa a etapa

Legenda de bloqueio:
**L** = executável localmente · **H** = exige decisão/assinatura humana ·
**X** = exige recurso externo (API, infraestrutura)

| # | Etapa | Artefato | Bloqueio |
|---|---|---|---|
| 0 | Gate 2 | `gate2_approval_receipt/v1` | ✅ concluído |
| 1 | Run context | `migration_run_context/v1` | L + H (assinatura) |
| 2 | Decisão de entrega | `delivery_mode_decision_receipt/v1` | L + H |
| 3 | Evidência legada Step 2 | `legacy_step2_implementation_evidence/v1` | L (repo em `d26c73d` acessível) |
| 4 | Manifesto de decomposição | `decomposition_manifest/v1` | L (inventário de 376 paths) |
| 5 | Cabeça de decomposição | `decomposition_manifest_head/v1` | L |
| 6 | **PR 1** — packaging, schemas, registry, ProviderPort | código | L |
| 7 | **GOV 1** — sandbox selado, MCP, governança de wheel | `sealed_sandbox_profile/v1`, `wheel_build_provenance/v1`, `wheel_boundary_report/v1`, `mcp_rejection_matrix_report/v1` | L |
| 8 | Convergência PR1+GOV1 | — | L |
| 9 | **PR 2** — análise pura e tabelas-verdade | código | L |
| 10 | **PR 3** — adapter Pipeboard offline + 7A | `negative_security_test_report/v1`, `certification_7a_record/v1` | L |
| 11 | Convergência GOV1 final | `gov1_convergence_record/v1` | L |
| 12 | **PR 4** — Parquet, snapshots, DuckDB | código | L |
| 13 | Legacy seam PR — projeção dupla | `legacy_seam_release/v1`, `legacy_seam_contract/v1` | L + H |
| 14 | **PR 5** — seam adapter granular e paridade | `seam_parity_record/v1` | L |
| 15 | Hermes — adapter de consumidor, flag OFF | `ibvi_ads_delegation_contract/v1` | L + H |
| 16 | Ativação de leitura ao vivo | `smart_ads_live_read_activation_receipt/v1` | H (decisão protegida) |
| 17 | **GATE 3** — seleção de versão | `gate3_selection_receipt/v1`, `gate3_evidence_packet/v1`, `gate3_freshness_profile/v1` | H + **X** |

Depois do Gate 3 ainda vêm: autorização de workload identity, deploy e verificação de
configuração, as duas chamadas ao vivo com autorização e reserva independentes,
reconciliação 7B, transição de certificação, shadow mode, paridade de seam, rollback e
Gate 4 (readiness).

## O gargalo real

As etapas 1-15 são **inteiramente executáveis** com o que já existe: o toolkit de
governança, o repositório legado em `d26c73d` (acessível, 376 paths) e o repo atual.
Nada nelas depende da Meta.

O primeiro bloqueio externo verdadeiro é a etapa 16/17. Ou seja: o caminho até o Gate 3
é trabalho de implementação, não de espera.

## Observações sobre o esforço

- **Etapa 4** é a mais subestimada. O `source_inventory/v1` exige, por item, um
  `source_selector` com `parser_abi`, `byte_range`, `raw_span_digest` e `ast_digest` —
  digest de AST por símbolo, não por arquivo. Com `coverage_assertion` exigindo
  `unassigned_item_count: 0` e `duplicate_assignment_count: 0`, a cobertura precisa ser
  total e sem ambiguidade.
- **Etapas 6-12** são o corpo do produto (o read gateway em si) e dominam o cronograma.
- **Etapa 7 (GOV1)** roda em paralelo com PR1; ambas convergem na etapa 8.

## Próximo passo concreto

Emitir e assinar o `migration_run_context/v1` (etapa 1) e o
`delivery_mode_decision_receipt/v1` (etapa 2). Os builders estão no PR #10; o
procedimento de assinatura é o mesmo do Gate 2 — a chave privada nunca sai da máquina do
operador.
