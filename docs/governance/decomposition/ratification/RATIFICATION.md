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
[`RUNTIME-CONTRACT.ratified.md`](RUNTIME-CONTRACT.ratified.md). O delta não
ratificado está em
[`RUNTIME-CONTRACT.ratified-to-main.diff`](RUNTIME-CONTRACT.ratified-to-main.diff),
um diff unificado entre esse arquivo e o contrato em `main`, também embutido
no registro. Instalar como ratificado o contrato tal como está em `main`
exige antes uma decisão explícita sobre esse delta; este registro não a toma.

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
