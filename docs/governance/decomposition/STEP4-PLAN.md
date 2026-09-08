# Etapa 4 — plano de preparação e implementação

Status: preparação e builder local de candidatos implementados, sem commit;
manifesto final e admissão do perfil ainda não implementados. Base `d18ac69f40693a89a969307661cecbf5e823f780`.
Branch local `governance/decomposition-step4-plan`.

## Objetivo e limite desta entrega

Preparar um caminho executável para gerar `MIGRATION_DECOMPOSITION_MANIFEST.json`
a partir do legado fixado, com inventário completo, decisões exatas por unidade
e verificação independente de digests/cobertura. A autorização atual cobre
emenda proposta, implementação, testes e artefatos locais; não abrange commit, assinatura, push, PR, merge,
head ativo da etapa 5 ou execução de código legado.

O manifesto só pode ser apresentado como assinável depois do fechamento de
[CONTRACT-PROPOSALS.md](CONTRACT-PROPOSALS.md). Esta preparação não cria um
JSON com `$schema: smart_ads/decomposition_manifest/v1` incompleto nem valores
`approved` escolhidos pelo executor.

## Evidência já obtida

- Nove objetos do store: hashes e assinaturas válidos. Gate 2 aprovado, decisão
  manual assinada, run context e identidade do ADR coerentes. O ADR corrente
  tem os mesmos bytes aprovados no Gate 2.
- Escopo do Git: 30 caminhos das raízes + 14 associados = 44, sem exclusões;
  digest `a0f50b3c…32d` igual ao ADR. Total do repositório: 376.
- Pinna: 18 arquivos, sendo 16 Python; README/config preservados no universo.
- Python 3.12 real disponível. O vetor conductor reproduz `[597,1350]`, raw
  `bfa964d5…3dd8` e AST `28021585…5f3` exatamente.
- Catálogo exploratório de 1.131 símbolos com ranges e hashes; pais e filhos
  ainda se sobrepõem. Catálogo não equivale a inventário selecionado.
- Builder/CLI de candidatos locais implementado; nenhum domínio P1 correspondente
  foi registrado. A execução real resolve 122 unidades disjuntas, todas pendentes.
- Registry época 3 não autoriza o schema; perfil de contratos ainda não materializado.

## Arquitetura proposta

Reutilizar `tools/governance/jcs.py`, `locator.py`, `p1.py` e os padrões CLI já
testados. Não mover o toolkit nesta tarefa nem introduzir import do tooling em
um futuro wheel `src/smart_ads`. Módulos locais implementados:

| Módulo | Responsabilidade |
|---|---|
| `tools/governance/decomposition_scope.py` | Git somente leitura, identidade pinada, expansão completa e digests dos caminhos |
| `tools/governance/decomposition_selectors.py` | seletores fechados, bytes, parser ABI, IDs, sobreposições e regiões residuais |
| `tools/governance/decomposition_decisions.py` | enums e relações status/mode/target, autoridade de diferimento e invariantes |
| `tools/governance/decomposition.py` | montagem determinística e verifier de candidato genesis; correções ainda não suportadas |

CLI local: `resolve-decomposition-inventory`, `build-decomposition-manifest`,
`verify-decomposition-manifest`. A última verifica sem consultar credenciais ou
provedores. O candidato não tem schema de envelope nem integrity e é recusado
por `sign` e `store-put`. Esses comandos ficam posteriores, sob o contrato
de assinante e os pontos de assinatura humana. Nenhuma CLI de head nesta etapa.

## Sequência de trabalho

| Task | Dependência | Arquivos / entrega | Critério de aceite |
|---|---|---|---|
| T0 — fechar contrato | nenhuma | emenda de D1; schema complementar D2–D4 e plano atualizado | ausência de ciclos de hash; chaves de objetos e pré-condições explícitas; propostas ratificadas antes de status aprovados |
| T1 — resolver escopo | T0 para contrato final; dados já disponíveis | `decomposition_scope.py`, testes de Git herméticos | exatamente os 44 blobs e o digest pinado; recusa commit/tree alterados, root ausente, submodule/symlink inadequado, exclusão implícita |
| T2 — seletores e IDs | T1 | `decomposition_selectors.py`, goldens | CPython 3.12; conductor literal; Unicode/CRLF/decoradores; duplicatas e sobreposições detectadas; nada executa o legado |
| T3 — decisões por unidade | T2, D3 | arquivo de decisões revisável, unidades de segurança separadas | cada ID exatamente uma vez; destinos permitidos; Pinna/funnel/Google diferidos corretamente; nenhuma aprovação inferida |
| T4 — builder/verifier | T0–T3 | `decomposition.py`, CLI, schema e testes | digests/contagens recomputados; equality de sets; predecessor válido; assinaturas e locators separados |
| T5 — integração de perfil | D4, T4 | teste de registry/owner/profile e preflight de emissão | signer/action/schema/época/tempo demonstrados; perfil ausente ou incompatível bloqueia; sem assinar na sessão |
| T6 — geração local revisável | T4–T5 | manifesto sem assinatura, params portáveis, inventário e decisões | rebuild determinístico; nenhuma entry pendente; counts sem unassigned/duplicados/conflitos; nonce/efeito não fabricados |
| T7 — revisão e evidências finais | T6 | relatório, testes e manifesto de hashes | revisão vinculada ao HEAD e inputs finais; todos os checks verdes; somente então handoff de assinatura humana |

As tasks são uma ordem de dependências, não despacho de agentes nem autorização
de publicação. O caminho de assinatura/registro do perfil poderá precisar de
preparação adicional conforme D4; essa dependência não pode ser escondida por
uma fixture de teste. Para genesis não existe head anterior; o verifier pode
checar o predecessor em correções sem publicar CAS. A autoridade de tip/forks
permanece responsabilidade da etapa 5.

## Matriz mínima de verificação

1. **Git/escopo:** baseline descendente com mesmo nome de arquivo; árvore errada;
   arquivo removido/adicionado; expansão de fixture; 43/45 paths; dupla inclusão;
   exclusão sem autoridade; paths absolutos, `..`, escape por link e modo inválido.
2. **Seletores:** vetor real conductor; offsets UTF-8 vs caracteres; fim half-open;
   símbolo fora de faixa; bytes alterados; AST diferente; parser 3.13 recusado;
   decoradores/parametrização presentes em unidades; classe e filho duplicados.
3. **Decisões:** ID ausente/extra/duplicado; approved+defer; deferred com target;
   rejected com testes; Pinna enviado ao core; função/histórico sem owner; path
   que escapa do destino; split sem invariantes ou com invariantes conflitantes.
4. **Digests:** inventory/preimage/manifest recomputados; entradas reordenadas;
   campos extras; assinatura não muda manifest_digest sob D1 ratificado; locator
   do assinado difere do digest P1; não usar digest de arquivo como AST digest.
5. **Governança:** registry certa e errada; schema/action/role divergentes;
   signer fora de validade; decisão manual/run diferente; contract inventory
   ausente; predecessor adulterado, origem diferente ou timestamp não crescente.
6. **CLI/reprodução:** diretório temporário, source snapshot fixo e interpretador
   absoluto; erro não deixa manifesto parcial; teste não importa código do
   checkout vivo por editable install; reexecutar suite `tests/governance` ao
   integrar o builder. A suíte base de 166 testes não cobria o builder novo.

Não gerar testes que apenas espelhem tabelas internas. Usar contraexemplos e
comparação independente entre bytes Git, seleção, entradas e artefato final.
Regenerar evidência somente depois da última alteração aceita de código/testes.

## Artefatos locais desta preparação

Diretório: `~/Projects/_scratch/smart-ads-step4-PREP/`.

- `collect_step4.py`: coletor offline de observações; não é o futuro builder.
- `scope-observation.json`: 44 arquivos, OIDs, tamanhos, modos e hashes.
- `symbol-catalogue.json`: exploração de símbolos; explicitamente não é inventário.
- `collection-checks.json`: vetores reais e contagens observadas.
- `prerequisites.json`: verificação pública do store e igualdade de pré-condições.
- `digest-composition-probe.json`: demonstra a interpretação cíclica de D1 sem assinatura.
- `SHA256SUMS`: hashes dos artefatos finais desta preparação.

Reproduzir as observações com o CPython 3.12 instalado:

```bash
rtk proxy env PATH=/opt/homebrew/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  /opt/homebrew/bin/python3.12 \
  "$HOME/Projects/_scratch/smart-ads-step4-PREP/collect_step4.py"
```

Os caminhos do coletor histórico são locais e explícitos. A CLI recebe o clone
por argumento e confere commit, árvore e universo pinados; os testes Git usam
fixtures herméticas.

## Critério de conclusão

Esta entrega local termina com emenda proposta, builder de candidatos,
observações verificadas, testes e documentação.
A etapa 4 completa exige o manifesto final validado e o ciclo de assinatura/
publicação aplicável; não está concluída só porque o universo de 44 paths foi
enumerado. Não há assinatura, novo cell-object, commit, push, PR ou merge nesta
preparação.

## Estado das tasks após implementação local

- T0: emenda preparada em `ADR-AMENDMENT.proposed.patch`, sem aplicação ao ADR
  aprovado. D4 (bootstrap/profile/owner) permanece em aberto.
- T1/T2: resolver e seletores implementados; o inventário selecionado contém
  43 arquivos inteiros e 79 unidades AST/residuais do arquivo de segurança.
- T3: validação mecânica e template de 122 decisões implementados. Owner, destino,
  modo e status ficam nulos; a análise humana por unidade permanece pendente.
- T4: builder/verifier do subconjunto de candidatos genesis implementado,
  incluindo CLI e conferência dos predecessores em módulos separados.
- T5/T6: emissão admitida e manifesto final não implementados; nenhum teste
  sintético substitui o perfil ou a revisão das decisões.
- T7: testes e revisão locais documentados no relatório de implementação;
  a revisão do manifesto final permanece posterior a T5/T6.

O subconjunto atual recusa sobreposições, `target_selector` não nulo, destinos
compartilhados e correções. Para o arquivo de segurança exige a partição
canônica em definições externas e resíduos; isso expõe unidades para revisão,
mas não prova que os destinos preservam os invariantes. Consulte [README.md](README.md).

## Continuação autorizada: contrato e decisões propostas

D4 ganhou um contrato concreto de admissão e catálogo dos 116 perfis, mantendo
ratificação/instalação/verificador de runtime como estados pendentes explícitos.
T3 ganhou uma revisão para cada uma das 122 unidades, com human_decision e owner
ainda nulos. Os detalhes estão em `ADMISSION-CONTRACT.proposed.md` e
`UNIT-REVIEW.proposed.md`; o comando `prepare-decomposition-review` os reconstrói
como dados verificáveis. Nenhuma proposta do executor constitui aceitação.
