# Runbook — Toolkit de Governança Gate 2 (Smart Ads)

Guia operacional para um humano usar o toolkit em `tools/governance/` a fim de
gerar, assinar, verificar e armazenar os artefatos de governança do Gate 2
descritos na ADR-0001 (`docs/adr/ADR-0001-smart-ads-read-gateway.md`, seções
12.1-12.3 e a tabela de perfis P1 em torno da linha 3537).

**Nenhum comando deste toolkit gera chaves de produção nem chama rede por
conta própria** (exceto `check_branch_protection_via_gh`, que roda `gh api`
sob comando explícito do humano). Todas as operações Ed25519 usam o
`openssl` CLI via subprocess — não há dependência `cryptography`.

## 0. Pré-requisitos e o que ainda bloqueia

> **Estado em 2026-09-06.** Os itens abaixo descrevem o bloqueio que existia
> em 2026-09-03 e são mantidos como registro. Desde 2026-09-04: `main` está
> protegida (PR obrigatório, check `pytest` obrigatório, `enforce_admins`),
> o repositório é público, e o Gate 2 foi concedido — `gate2_approval_receipt/v1`
> em `cell-object:sha256:025558333632e8b7233151d7505ebff188e04cc2d46eced03b922bdc4e1514e0`,
> vinculado ao merge protegido `a3f19ef668748c64c5c679710c231426c5e05f6a`.
> As seções 1–7 estão concluídas; o caminho continua nas seções 8–10.

- `main` do repositório **não está protegida** (plano GitHub Free no momento
  desta implementação). A decisão de proteger `main` foi **adiada** por
  decisão humana — não é uma tarefa deste toolkit.
- Enquanto `main` não estiver protegida, `protected_merge_evidence/v1` **não
  pode ser produzido honestamente**. O builder
  (`artifacts.build_protected_merge_evidence`) recusa a construção a menos
  que o chamador prove explicitamente `branch_protection_verified=True`
  (nunca há valor default). A CLI (`build-merge-evidence`) exige um arquivo
  `--protection-json` com `{"protected": true}` — obtido via
  `check_branch_protection_via_gh` ou inspeção manual — como substituto
  offline da chamada de rede.
- Sem esse artefato, `gate2_approval_receipt/v1` pode ser **construído e
  assinado** (para fins de preparação/dry-run), mas não é uma autorização
  válida de efeito enquanto seu `protected_merge_evidence_locator` apontar
  para uma evidência que não existe/não foi assinada por evidência real de
  merge protegido.

## 1. Gerar chave do trust anchor e chave do operador (OFFLINE)

Rodar em uma máquina offline ou isolada, nunca dentro do repositório:

```bash
openssl genpkey -algorithm ed25519 -out trust-anchor.pem
openssl genpkey -algorithm ed25519 -out operator-ronaldo.pem
chmod 600 trust-anchor.pem operator-ronaldo.pem
```

Extrair a chave pública raw (base64) e o `key_id` de cada uma:

```bash
python3 -m tools.governance.cli key-id --pubkey-pem trust-anchor.pem
python3 -m tools.governance.cli key-id --pubkey-pem operator-ronaldo.pem
```

Guarde as chaves **privadas** fora do repositório (cofre de segredos, HSM, ou
disco criptografado offline). Apenas as chaves públicas (base64/hex) e os
`key_id` derivados entram nos artefatos versionados.

## 2. Build + pin do `cell_trust_anchor_config/v1`

```bash
python3 -m tools.governance.cli build-trust-anchor \
  --params trust_anchor_params.json \
  --out cell_trust_anchor_config.json
```

Este artefato **não é assinado via P1** — é ancorado fora de banda (ADR
seção 12.1: "A registry never self-authenticates with one of its own keys").
O comando também imprime `trust_anchor_pin` (`sha256:<hex>` do JCS do
artefato). Esse pin deve ser transportado para a configuração protegida fora
do repositório (ex.: variável de ambiente de produção, secret manager) — ele
é o que impede rollback do próprio trust anchor.

## 3. Build + assinar (anchor) + verificar + store-put do `key_authorization_registry/v1`

Inclua uma entrada para o operador (ex.: Ronaldo) autorizada para
`(gate2_approval_receipt/v1, gate2_approve)`:

```bash
python3 -m tools.governance.cli build-registry \
  --params registry_params.json --out registry_unsigned.json

python3 -m tools.governance.cli sign \
  --schema key_authorization_registry/v1 \
  --key trust-anchor.pem \
  --in registry_unsigned.json --out registry_signed.json

python3 -m tools.governance.cli verify \
  --schema key_authorization_registry/v1 \
  --pubkey-raw-base64 <trust-anchor raw pubkey base64> \
  --in registry_signed.json

python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects \
  --in registry_signed.json
```

Guarde o locator impresso por `store-put` — ele é `key_registry_snapshot_locator`
para os próximos artefatos.

## 4. Build + assinar (anchor) + verificar + store-put do `gate2_authority_policy/v1`

`designated_principals` usa o formato assumido `["principal:ronaldo"]` (ver
seção "Premissas"). `ci_review_policy_digest` é o `sha256:<hex>` do JSON de
branch protection/rulesets aplicado — **só existirá depois que `main` for
protegida**.

```bash
python3 -m tools.governance.cli build-policy \
  --params policy_params.json --out policy_unsigned.json

python3 -m tools.governance.cli sign \
  --schema gate2_authority_policy/v1 \
  --key trust-anchor.pem \
  --in policy_unsigned.json --out policy_signed.json

python3 -m tools.governance.cli verify \
  --schema gate2_authority_policy/v1 \
  --pubkey-raw-base64 <trust-anchor raw pubkey base64> \
  --in policy_signed.json

python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects \
  --in policy_signed.json
```

## 5. BLOQUEADO até proteção — `protected_merge_evidence/v1`

`build-merge-evidence` faz, **por padrão**, a checagem AO VIVO via
`gh api repos/<repo>/branches/<ref>` (função
`artifacts.check_branch_protection_via_gh`). Isso exige `--repository` e
`--ref`:

```bash
python3 -m tools.governance.cli build-merge-evidence \
  --params merge_params.json \
  --repository aiconnai/smart-ads --ref main \
  --out protected_merge_evidence_unsigned.json
```

Omitir `--repository`/`--ref` (sem fornecer `--protection-json`) é erro de
uso (`exit 2`) — a CLI nunca cai silenciosamente em um caminho offline.

Existe um substituto offline (`--protection-json <arquivo>`) apenas para
quando a checagem ao vivo genuinamente não está disponível (ex.: ambiente
sem acesso à API do GitHub). Esse caminho **exige** também
`--offline-protection-ack I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE` (o literal
exato) e emite um aviso em stderr — para que o caminho offline nunca seja
usado casualmente no lugar de evidência real:

```bash
python3 -m tools.governance.cli build-merge-evidence \
  --params merge_params.json \
  --protection-json protection.json \
  --offline-protection-ack I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE \
  --out protected_merge_evidence_unsigned.json
```

Em qualquer um dos dois caminhos, `protected_merge_evidence/v1` só pode ser
produzido honestamente depois que:

1. `main` for protegida (branch protection rules / rulesets), e
2. o merge PR real acontecer sob essa proteção, e
3. a checagem (ao vivo ou, excepcionalmente, offline com o ack acima)
   confirmar `protected: true` para o SHA correspondente.

O caminho offline serve apenas para preparação/dry-run local — nunca deve
substituir a checagem ao vivo na produção real do artefato que autoriza o
Gate 2.

## 6. Build + assinar (operador) + verificar + store-put do `gate2_approval_receipt/v1`

Sobre a identidade candidata atual (**válida apenas se o merge protegido do
passo 5 for exatamente este SHA** — se `main` precisar ser re-mergeada sob
proteção, a identidade muda e este passo deve ser refeito):

- `approved_adr_git_identity.commit_sha` = `merge 46e468d983989e85103b1ba967ce6c3bb943626d`
- `approved_adr_git_identity.git_blob_oid` = `a4a8c06b44e929b3562336dff86b61a55e10f79f`
- `approved_adr_git_identity.file_content_sha256` = `sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e`
- `approved_adr_git_identity.path` = `docs/adr/ADR-0001-smart-ads-read-gateway.md`
- `legacy_source_identity` = `{"repository": "mbras-tech/mbras-campaigns", "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"}` (fixo, validado pelo builder)

```bash
python3 -m tools.governance.cli build-receipt \
  --params receipt_params.json --out receipt_unsigned.json

python3 -m tools.governance.cli sign \
  --schema gate2_approval_receipt/v1 \
  --key operator-ronaldo.pem \
  --in receipt_unsigned.json --out receipt_signed.json

python3 -m tools.governance.cli verify \
  --schema gate2_approval_receipt/v1 \
  --pubkey-raw-base64 <operator raw pubkey base64> \
  --in receipt_signed.json

python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects \
  --in receipt_signed.json
```

## 7. Verificação independente + PR

1. Peça a uma segunda pessoa (ou re-execute você mesmo em máquina separada)
   `verify` em cada artefato assinado, usando a chave pública correta.
2. Abra um PR contendo apenas os `cell-object`s novos sob
   `docs/governance/cell-objects/` e os JSON de parâmetros usados (sem
   chaves privadas).
3. Merge e ativação do Gate 2 exigem autorização humana literal — nenhum
   comando deste toolkit avança o run automaticamente após `store-put`.

---

# Pós-Gate 2 — etapas 1 e 2 do `docs/governance/PATH-TO-GATE3.md`

As seções 8–10 cobrem `migration_run_context/v1` (ADR L2891-2893, perfil P1
`SMART-ADS:RUN-CONTEXT:V1\n`, signer "run initializer") e
`delivery_mode_decision_receipt/v1` (ADR L2895-2900, perfil P1
`SMART-ADS:DELIVERY-MODE:V1\n`, signer "delivery decision owner"). Ambos são
`H` na tabela de perfis: validade histórica de emissão, revalidada com `E`
antes de qualquer efeito. Nenhum deles chama rede. **Não** avançam para Gate 3,
chamadas ao vivo nem implementação do gateway.

## 8. Registry época 2 — habilitar as ações do run

A registry época 1 (`cell-object:sha256:4b0da88a…`) autoriza apenas
`registry_issue`, `policy_issue`, `merge_evidence_issue` (trust anchor) e
`gate2_approve` (operador). Os dois artefatos novos exigem ações próprias, e a
ADR (L2768-2778) manda que cada artefato assinado referencie exatamente uma
snapshot imutável cuja entrada permita o par `(schema, action)`. Logo a
primeira etapa é uma **nova** registry, aditiva, com `epoch: 2`:

| Entrada | Ação nova | Schema |
|---|---|---|
| `principal:smart-ads-trust-anchor` (chave do trust anchor) | `run_context_initialize` | `smart_ads/migration_run_context/v1` |
| `principal:ronaldo` (chave do operador) | `delivery_mode_decide` | `smart_ads/delivery_mode_decision_receipt/v1` |

Regras: mesmas chaves e mesmos `key_id` da época 1 (não gerar chave nova);
`epoch` estritamente maior; a época 1 permanece no store como proveniência
histórica dos artefatos do Gate 2 e **não** é apagada nem reescrita.

```bash
python3 -m tools.governance.cli build-registry \
  --params params_registry_epoch2.json --out registry_epoch2_unsigned.json
python3 -m tools.governance.cli sign \
  --schema key_authorization_registry/v1 \
  --key trust-anchor.pem \
  --in registry_epoch2_unsigned.json --out registry_epoch2_signed.json
python3 -m tools.governance.cli verify \
  --schema key_authorization_registry/v1 \
  --pubkey-raw-base64 <trust-anchor raw pubkey base64> \
  --in registry_epoch2_signed.json
python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects --in registry_epoch2_signed.json
```

Guarde o locator impresso: ele é o `key_registry_snapshot_locator` das seções
9 e 10.

Estado: **executado em 2026-09-06**; snapshot época 2 =
`cell-object:sha256:0a65b123f05234f563f4fa65f5fdb2354e58286fd98dabda727dccb754a87fdf`.

## 9. `migration_run_context/v1` — build + assinar (run initializer) + verificar + store-put

### 9.1 Identidade do run (convenção vigente — não criar uma segunda)

| Campo | Valor | Derivação |
|---|---|---|
| `tenant_ref` | `tenant:mbras` | prefixo `tenant:` + o campo `tenant` das entradas da registry (`"mbras"`), mesmo padrão de `principal:<slug>` |
| `cell_ref` | `cell:smart-ads-migration` | prefixo `cell:` + nome da célula de migração deste ADR; único cell definido |
| `run_id` | `run:gate2:<content_digest hex do gate2_approval_receipt/v1>:<seq>` | "unique run derived from Gate 2" (tabela de perfis L3547): o run é nomeado pelo digest do receipt que o originou, mais um sequencial começando em `1` |
| `created_at_utc` | instante da construção efetiva, UTC, `YYYY-MM-DDTHH:MM:SSZ` | nunca pré-datado nem copiado de outro artefato |

Valores em vigor (run 1):

- `run_id` = `run:gate2:025558333632e8b7233151d7505ebff188e04cc2d46eced03b922bdc4e1514e0:1`
- `gate2_receipt_locator` = locator do receipt em `cell-object:sha256:025558333632…`
- `approved_adr_git_identity` = **byte-idêntica** à do receipt (commit `a3f19ef6…`, blob `a4a8c06b…`, sha256 `239b53e0…`); o builder valida a forma, mas a igualdade com o receipt é responsabilidade de quem monta os params
- `legacy_source_identity` = fixa (`mbras-tech/mbras-campaigns@d26c73d8…`), validada pelo builder
- `signer_key_id` = `key_id` do trust anchor (`key:ed25519:2d20788f…`), papel "run initializer", com `run_context_initialize` na registry época 2
- `key_registry_snapshot_locator` = snapshot época 2 (seção 8)

Um segundo run sob o **mesmo** receipt (p.ex. após um rollback que exija
novo run context) usa `:2`, nunca reutiliza `:1`. Um novo Gate 2 gera um novo
digest e reinicia a sequência em `:1`.

### 9.2 Comandos

```bash
python3 -m tools.governance.cli build-run-context \
  --params params_run_context.json --out run_context_unsigned.json
python3 -m tools.governance.cli sign \
  --schema migration_run_context/v1 \
  --key trust-anchor.pem \
  --in run_context_unsigned.json --out run_context_signed.json
python3 -m tools.governance.cli verify \
  --schema migration_run_context/v1 \
  --pubkey-raw-base64 <trust-anchor raw pubkey base64> \
  --in run_context_signed.json
python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects --in run_context_signed.json
```

`params_run_context.json` contém exatamente: `gate2_receipt_locator`,
`approved_adr_git_identity`, `legacy_source_identity`, `tenant_ref`,
`cell_ref`, `run_id`, `created_at_utc`, `key_registry_snapshot_locator`,
`signer_key_id`. Chaves privadas nunca entram em params nem no repositório.

Estado: **executado em 2026-09-06T15:23:44Z**; run context =
`cell-object:sha256:e00667aeac303c63695180ebfba8539b99f80734ae001b0313d45129ca5f3a38`.

## 10. `delivery_mode_decision_receipt/v1` — build + assinar (operador) + verificar + store-put

Contém o locator exato do receipt do Gate 2, a identidade do ADR byte-idêntica,
o locator do run context da seção 9 e `delivery_mode: manual`. O builder **não
aceita** `delivery_mode` como parâmetro: o schema v1 admite apenas `manual` e
não possui campo de evidência autônoma (ADR L2898-2899). Autoriza a identidade
do ADR mergeada sob proteção, não a baseline legada.

Signer: o humano designado (`principal:ronaldo`, chave do operador,
`key:ed25519:55e6ef88…`) com `delivery_mode_decide` na registry época 2.
`decided_at_utc` é o instante da construção efetiva.

```bash
python3 -m tools.governance.cli build-delivery-mode \
  --params params_delivery_mode.json --out delivery_mode_unsigned.json
python3 -m tools.governance.cli sign \
  --schema delivery_mode_decision_receipt/v1 \
  --key operator-ronaldo.pem \
  --in delivery_mode_unsigned.json --out delivery_mode_signed.json
python3 -m tools.governance.cli verify \
  --schema delivery_mode_decision_receipt/v1 \
  --pubkey-raw-base64 <operator raw pubkey base64> \
  --in delivery_mode_signed.json
python3 -m tools.governance.cli store-put \
  --root docs/governance/cell-objects --in delivery_mode_signed.json
```

`params_delivery_mode.json` contém exatamente: `gate2_receipt_locator`,
`approved_adr_git_identity`, `run_context_locator`, `decided_by_principal_ref`,
`decided_at_utc`, `key_registry_snapshot_locator`, `signer_key_id`.

Publicação: um único PR com os três cell-objects novos (registry época 2, run
context, delivery mode) e os JSON de params (sem chaves privadas), seguindo a
seção 7. Merge exige autorização humana literal. Após o merge, o próximo passo
é a etapa 3 do `PATH-TO-GATE3.md` (`legacy_step2_implementation_evidence/v1`),
fora do escopo deste runbook.

## Premissas (assunções explícitas)

- **Formato de `principal_ref`**: assumido como `"principal:<slug>"`
  (ex.: `"principal:ronaldo"`). A ADR não fixa um formato de string; este é
  um formato de trabalho, não normativo.
- **`key_authorization_registry/v1`.`integrity.key_registry_snapshot_locator`
  = `null`**: assumido como o sentinel de bootstrap. A ADR diz que "a
  registry never self-authenticates with one of its own keys" e que a
  verificação da registry é contra o trust anchor (bootstrap), não contra
  outra registry. Este toolkit modela isso como locator `null` mais
  verificação de `integrity.key_id` contra a chave do trust anchor
  (fornecida explicitamente pelo chamador do builder — nunca derivada da
  string legível `trust_anchor_id`).
- **Armazenamento em `docs/governance/cell-objects/` satisfaz
  `cell_immutable_object`**: assumido para os fins deste toolkit local; a
  ADR não define a implementação física do "cell immutable object store",
  apenas seu contrato de endereçamento por conteúdo.
- **`gate2_authority_policy/v1` assinado pela chave do trust anchor**: a ADR
  descreve o signer como "external governance anchor" (tabela de perfis);
  assumido aqui como a mesma chave de `cell_trust_anchor_config/v1`, não uma
  chave de policy separada — não há artefato ou seção que defina uma chave
  distinta.
- **Identidade candidata do passo 6 é válida apenas para o SHA de merge
  específico ali listado.** Qualquer re-merge sob proteção real invalida os
  valores fixados e exige regeneração de `gate2_approval_receipt/v1`.
- **Formato de `tenant_ref` / `cell_ref` / `run_id`** (seção 9.1): a ADR só
  exige que o run context "binds tenant, cell" e seja "unique run derived from
  Gate 2"; os prefixos `tenant:` / `cell:` / `run:gate2:<digest>:<seq>` são
  convenção de trabalho deste toolkit, escolhida para espelhar
  `principal:<slug>` e para que o `run_id` seja derivável do receipt sem
  estado externo. Não normativos.
- **Signer do `migration_run_context/v1` = chave do trust anchor**: a tabela
  de perfis nomeia o papel "run initializer" sem definir uma chave própria;
  assumido como a chave do trust anchor, habilitada por `run_context_initialize`
  na registry época 2. Se um dia existir uma chave dedicada de inicialização,
  basta uma nova época de registry.
- **Bump de época da registry é aditivo**: a época 1 continua resolvível e
  válida como snapshot histórico dos artefatos que a referenciam (receipt do
  Gate 2, policy, evidência de merge). Verificação `E` no momento de um efeito
  deve usar a época corrente mais alta, conforme ADR L2781-2790.
