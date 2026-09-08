# Etapa 4 — ratificação humana materializada

Registro, no repositório, da ratificação humana dos contratos propostos da
etapa 4 e das 122 disposições por unidade. Os fatos vinculados por hash estão
em [`ratification-record.json`](ratification-record.json); as disposições
com decisão preenchida estão em
[`dispositions.ratified.json`](dispositions.ratified.json).

## O que foi ratificado

Em 2026-09-08T02:50:28Z, `principal:ronaldo` respondeu três perguntas
explícitas numa sessão de agente:

- contrato: ratificar como proposto — D1–D4 e suplemento v2, com as
  condições listadas;
- disposições: aceitar as 122 como recomendadas — 96 aprovadas, 26 deferidas;
- `system_owner`: `principal:ronaldo` para as 122.

Os bytes ratificados são os identificados por hash no registro. Cinco das
entradas coincidem com o que está em `main`. A sexta, o contrato de runtime,
diverge de `main` por exatamente um parágrafo, acrescentado depois da
ratificação por direção explícita e mergeado no PR #16.

Para que os bytes ratificados sejam recuperáveis sem depender de nada fora
do repositório, eles estão versionados aqui em
[`RUNTIME-CONTRACT.ratified.md`](RUNTIME-CONTRACT.ratified.md). O delta que ficou
fora da ratificação original está em
[`RUNTIME-CONTRACT.ratified-to-main.diff`](RUNTIME-CONTRACT.ratified-to-main.diff),
um diff unificado entre esse arquivo e o contrato em `main`, também embutido
no registro. O registro original não ratifica esse delta; a decisão posterior
está materializada na emenda M2 abaixo.

## Emenda posterior — ratificação de M2

A ratificação explícita de M2 por `principal:ronaldo` foi materializada em
2026-09-08T19:09:28Z em
[`ratification-amendment-M2.json`](ratification-amendment-M2.json).
A data é a da materialização, não um horário exato atribuído à mensagem humana.

A emenda vincula o delta
`sha256:cc4f69e7c8b7c515c292200ccbee4bb3bac3c29bd4b7c7b057be317ae82554c7`
e incorpora à ratificação o contrato de runtime resultante
`sha256:26061f317548841b0d3dfaec3ee1199f05d9724073162b51337d0c8a4f8193af`,
identificado por caminho e blob no snapshot `586dcd3` de `main`.

O registro de 02:50:28Z e os bytes originalmente ratificados permanecem
inalterados. A emenda não retroage essa aprovação nem modifica as 122
disposições ou suas condições. Instalação, integração do runtime e assinaturas
continuam sendo ações separadas; a emenda não remove os bloqueios do CLI.

## O que este registro não é

Não é envelope assinado, não confere autoridade e não admite nada. Os três
bloqueios de admissão são uma constante do código, emitida em todo candidato,
e só o caminho do runtime protegido pode admitir. O `verify` continua
reportando `INCOMPLETE` com os mesmos três bloqueios depois deste registro,
e isso é o esperado.

## Artefato derivado não versionado

O candidato ratificado (`sha256:03fba796…`) não é versionado. Ele é
reconstruído byte a byte a partir de `dispositions.ratified.json` com o
comando registrado no JSON e `--generated-at 2026-09-08T02:50:28Z`.

## O que vem depois, na ordem do contrato

Instalação da configuração protegida; integração autenticada de head, relógio
e checkpoint; inventário de contratos assinado; manifesto assinado; atestação
da revisão humana. Nenhum desses passos é implicado por este registro.
