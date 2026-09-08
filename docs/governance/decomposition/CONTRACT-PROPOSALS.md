# Contrato da etapa 4 — propostas para revisão

Base examinada: `d18ac69f40693a89a969307661cecbf5e823f780`.
ADR: `docs/adr/ADR-0001-smart-ads-read-gateway.md`, SHA-256
`239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e`.
Este documento propõe decisões; não altera o ADR aprovado nem constitui aprovação
humana, schema registrado, manifesto, assinatura ou autoridade operacional.

## Fatos já determinados

- §9.2, linhas 2101–2144: 8 raízes + 14 entradas associadas; expansão em
  30 + 14 = **44 arquivos**, nenhum excluído. O repositório inteiro tem 376 paths.
- Commit legado `d26c73d8508c7c3d43161fe36a80c44a46bf0f2d`; árvore
  `68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798`.
- Digest JCS do universo ordenado:
  `sha256:a0f50b3c10c145902851dec67c8e5a45e91ed5f9bffb463039a9d2cc7cdef32d`.
- A pasta Pinna contém 18 arquivos: 16 Python (incluindo `__init__.py`), README
  e config. Os dois adicionais não podem ser omitidos. Não se deve afirmar que
  todo arquivo Python contém uma chamada mutante sem análise de seu conteúdo.
- Seletores `ast_symbol`, `whole_file` e `text_region` são permitidos, não apenas AST.
- Os enums de destino, modo, status e layer e as combinações válidas já estão
  fechados em §9.2, linhas 2220–2268; não se propõem novos valores.
- A assinatura do manifesto usa P1, papel `decomposition owner`, política H na
  geração e domínio `SMART-ADS:DECOMPOSITION:V1\n` (§12.7, linha 3551).

## D1 — composição de digest do manifesto e P1

As linhas 2211–2213 definem `manifest_digest` sobre o manifesto completo,
excluindo somente `manifest_digest`. As linhas 3482–3502 definem P1 sobre o
envelope excluindo somente os dois campos de resultado de assinatura.
O exemplo do §9.2 não contém `integrity`. Se "manifesto completo" for o envelope
P1 final, o digest inclui a assinatura, enquanto a assinatura inclui esse digest.
Reescrever o digest após assinar muda o preimage P1. Uma sonda de hash offline
reproduz essa dependência, sem gerar assinatura.

**Proposta recomendada, requer emenda explícita:** definir o payload sem
`integrity`; `manifest_digest = SHA256(JCS(payload sem manifest_digest))`.
Depois adicionar `integrity` e aplicar P1 sem alterar sua regra genérica.
O digest do inventário permanece `SHA256(JCS(source_inventory sem inventory_digest))`.
Assim, digest semântico, digest P1 e digest do locator assinado têm funções
distintas e não precisam ser iguais.

Ordem determinística: seletores → inventory IDs → inventory_digest → entries e
coverage → manifest_digest → integrity de entrada → P1 → assinatura humana →
locator dos bytes assinados. O builder deve recusar emissão final enquanto essa
fronteira não estiver ratificada. Não corrigir silenciosamente `p1.py`.

## D2 — identidade e fechamento dos seletores

O ADR fixa a forma de `ast_symbol` e o prefixo `source-unit:`, mas não fornece
o preimage de `inventory_id`, a grafia de todos os campos das outras duas
variantes nem as regras de qualificação de símbolos e `coverage_role`.

**Proposta de contrato complementar para o builder:**

1. `inventory_id = "source-unit:" + SHA256(JCS({repository, commit_sha,
   source_path, source_selector_digest}))`, hex minúsculo sem prefixo adicional.
2. `ast_symbol`: exatamente os seis campos do exemplo (kind, nome qualificado,
   ABI, intervalo, raw digest, AST digest). `source_digest` externo = AST digest.
   ABI real CPython 3.12; registrar também a versão concreta da ferramenta nas
   evidências. Não usar `feature_version` de outro runtime como substituição.
3. `whole_file`: exatamente `selector_kind`, `byte_range`, `raw_span_digest`,
   `file_mode`; intervalo `[0,len(blob)]`, modo Git literal. Source digest = raw.
4. `text_region`: exatamente `selector_kind`, `selector_abi`, `byte_range`,
   `raw_span_digest`; ABI proposta `raw_bytes:half_open_v1`. Source digest = raw.
5. `symbol_name`: qualificação lexical com `.`, com identidade desambiguada pelo
   intervalo; nomes iguais não substituem a identidade do seletor.
6. `coverage_role` proposto: `production_source`, `test`, `fixture`, `contract`,
   `documentation`. Registrar o enum como regra complementar, não fato já normativo.

Política de seleção recomendada: `whole_file` para disposição homogênea; símbolos
AST e regiões residuais para arquivo que precisa de divisão por invariante.
O catálogo contém 1.131 símbolos, incluindo pais/filhos: **não selecionar todos**.
Não emitir classe/função externa e filhos sobrepostos por acidente. Decoradores,
parâmetros de teste, imports, constantes, comentários relevantes e helpers devem
permanecer em uma unidade revisável; `ast.unparse(node)` sozinho não prova isso.
Para os arquivos divididos, propor cobertura de bytes por regiões disjuntas,
sem somar faixas sobrepostas. Sobreposição excepcional só com `split_group_id`
e invariantes de destino explicitamente disjuntos, conforme o ADR.

## D3 — decisões de migração e aprovação

`path-dispositions.proposed.json` cobre os 44 caminhos para revisão, mas não é
um conjunto de entries aprovadas. As decisões por sistema vêm de §9.2; caminhos
de destino concretos, preservação de helpers e testes de equivalência ainda
precisam de revisão por unidade selecionada.

- Ledger/controller e disablement ficam sob governança legada.
- Codex gates/scanners são tooling fora do wheel; testes vão para `tests/`.
- Funnel e Google ficam diferidos nas respectivas fases.
- Todo o corpus Pinna permanece fora da migração de leitura e segue o Write Plane.
- O conductor é candidato a reimplementação limpa no core, conforme o exemplo.
- `tests/test_security_boundaries.py` exige divisão por invariante: não portar
  indiscriminadamente testes históricos, de escrita e de infraestrutura para o core.

**Proposta:** a citação da decisão de diferimento deve vincular bytes e seção do
ADR aprovado; fechar sua representação em `deferral_authority_ref` no contrato
complementar. Não transformar texto de plano ou proposta do executor em aprovação.
Disposições não resolvidas bloqueiam `coverage_assertion` PASS.

## D4 — assinante e registry

As nove assinaturas do store existente foram verificadas offline. A registry
época 3 **não autoriza nenhuma chave para `decomposition_manifest/v1`**.
Ter a chave do anchor ou poder assinar não supre a autorização por schema/action.

**Proposta para futura decisão humana:** principal `principal:ronaldo` como
decomposition owner, action `decomposition_manifest_issue`, schema exato
`smart_ads/decomposition_manifest/v1`, em nova registry aditiva. O nome da action
e o vínculo ao papel são propostas: o ADR não os fixa. Preservar as épocas 1–3.
Não gerar chave nem registry emitida nesta preparação.

O perfil normativo de §12.7 também exige registro no
`artifact_contract_inventory/v1`; o store atual não contém esse artefato.
A tarefa do builder deve separar testes sintéticos do fechamento dessa cadeia,
sem declarar validado um perfil inexistente. Escopo da bootstrap authority e
forma executável do inventário devem ser reconciliados com o toolkit antes da
emissão assinável. A etapa 5 (`head`, CAS e forks) continua separada.

## Decisão antes de emitir o manifesto

Ratificar D1 e o fechamento de D2–D4 no desenho/contrato aplicável. Dados de
inventário e vetores de hash já podem ser usados no desenvolvimento; nenhuma
destas propostas é assinatura, autoridade de merge ou liberação da etapa 5.

## Emenda textual e subconjunto implementado

A emenda de D1–D3 está em
[ADR-AMENDMENT.proposed.patch](ADR-AMENDMENT.proposed.patch). Foi preparada
contra os bytes do ADR acima, sem aplicá-la: a identidade aprovada permanece
intacta. D4 ainda precisa de contrato de bootstrap/perfil/owner; não está
resolvido por essa emenda.

`step4-local-draft-v1` produz apenas candidato sem `$schema` de envelope nem
`integrity`, sempre `signable: false`. Aplica D1–D3 como proposta explícita;
não acrescenta domínio a `p1.py` e não emite `decomposition_manifest/v1`.

O resolver escolhe 43 arquivos inteiros e 79 unidades AST/residuais no arquivo
de segurança. Neste draft, esse arquivo exige exatamente a partição canônica
em definições externas e regiões residuais; renomear o arquivo inteiro como
`text_region`, ou cortá-lo em regiões arbitrárias, é recusado. A classificação
por invariantes e as decisões de destino continuam sendo revisão humana.
O template não infere owner: `system_owner` e `decision_status` começam nulos;
um status resolvido exige owner explícito.

O draft recusa seletores sobrepostos, `target_selector` não nulo, paths de
destino compartilhados e correções de manifesto. Essas recusas conservadoras
delimitam o que foi implementado; não revogam as formas admitidas no ADR.
`repository_tooling` exige layer homônimo no repo smart-ads e os caminhos de
tooling/testes definidos no contrato, impedindo entrada no wheel do core.

`STRUCTURALLY_VALID` descreve somente o candidato recomputado; não verifica
semanticamente invariantes escritos pelo operador. A CLI ainda retorna
`INCOMPLETE`/exit 5 por falta da admissão. Os predecessores públicos são
conferidos sem chave privada, mas o preflight final de perfil/owner não foi
implementado. Esta entrega não habilita assinatura nem fecha a etapa 4.

## Continuação D4 e revisão por unidade

O contrato de admissão está agora especificado em
[ADMISSION-CONTRACT.proposed.md](ADMISSION-CONTRACT.proposed.md), com os 116
perfis expandidos, bootstrap em seis passos e owner/ação propostos. O gerador
valida esse documento de dados por recomputação; os seis verificadores de
runtime continuam não implementados. Ratificação e instalação não foram realizadas.

[UNIT-REVIEW.proposed.md](UNIT-REVIEW.proposed.md) apresenta a revisão das 122
unidades, incluindo contexto, corpus de decoradores, dependências locais e
destinos compartilhados que exigem o contrato final de assembly/target_selector.
As propostas de aceitação não foram convertidas em decisões humanas.
