# Decomposição — builder local de candidatos

Novos candidatos usam `step4-local-draft-v2`, sob a
[emenda proposta](ADR-AMENDMENT.proposed.patch), ainda não ratificada. O comando
`build-decomposition-manifest` **gera um candidato**, não o manifesto admitido
`smart_ads/decomposition_manifest/v1`. Nenhum domínio P1 novo foi habilitado.

## Execução offline

Execute no checkout deste código com CPython 3.12 real. A seleção AST recusa
outro runtime; `feature_version` não substitui o parser ABI. O workflow pytest
foi fixado em Python 3.12 por esse motivo; os comandos anteriores continuam
com o requisito de versão geral do projeto.

```bash
python3.12 -m tools.governance.cli resolve-decomposition-inventory \
  --legacy-repo /caminho/para/mbras-campaigns \
  --out /diretorio/local/inputs.json

python3.12 -m tools.governance.cli build-decomposition-manifest \
  --legacy-repo /caminho/para/mbras-campaigns \
  --params /diretorio/local/inputs.json \
  --generated-at 2026-09-07T00:00:00Z \
  --out /diretorio/local/candidate.json

python3.12 -m tools.governance.cli verify-decomposition-manifest \
  --legacy-repo /caminho/para/mbras-campaigns \
  --in /diretorio/local/candidate.json
```

Substitua os caminhos locais e a data ilustrativa. A data é um argumento
explícito para permitir reprodução; não constitui atestação de tempo.
Cada saída deve usar um caminho novo. A escrita é atômica e recusa sobrescrita.
Uma falha no fsync/readback posterior à criação pode deixar o arquivo final:
inspecione-o; não trate qualquer erro de I/O como prova de ausência de arquivo.
Não é feita chamada de rede, checkout ou execução/import do código legado.
O Git lê os blobs do commit e árvore pinados, sem substituição por estado de
working tree, Git replace ou baseline arbitrária.

`resolve` e `build` retornam exit 0 se produziram o artefato local. Isso não é
PASS de admissão. `verify` recomputa o candidato e consulta os predecessores
públicos locais; retorna `INCOMPLETE`, exit **5**, enquanto este modo de draft
estiver em uso. Dados inválidos são recusados com erro, sem promover o candidato.

## Revisão dos inputs

O inventário real contém 44 paths e 122 unidades: 43 arquivos inteiros e 79
definições AST/regiões residuais do arquivo de segurança. O template deixa
owner, status, modo e destino nulos. Não aceite em lote decisões só para zerar
a contagem. Preencha cada unidade com a análise do código, invariantes e testes
adequados; um status resolvido exige owner explícito.

O verificador exige IDs atribuídos exatamente uma vez, cobertura de todos os
bytes, seletores recomputados e combinações válidas de status/modo/destino.
Tooling fica fora do wheel. O arquivo de segurança exige a partição canônica
em definições externas e resíduos: uma região de texto integral ou um corte
arbitrário não substitui a separação das unidades.

O v2 aceita seletores de retenção exata e assemblies de decorador/definição,
conforme [RUNTIME-CONTRACT.proposed.md](RUNTIME-CONTRACT.proposed.md). Demais
destinos compartilhados, sobreposição e correções/supersession são recusados.
Candidatos v1 continuam verificáveis pelas regras originais.

## Limite de autoridade

O candidato não tem `$schema` de envelope nem `integrity` e sempre informa
`signable: false`. `sign` e `store-put` existentes o recusam. Seu digest é do
payload proposto, não de um objeto P1 assinado. `STRUCTURALLY_VALID` é somente
consistência mecânica; os invariantes declarados não são provados pelo builder.

Os bloqueios explícitos são a emenda não ratificada, o perfil não admitido e a
revisão humana das decisões não atestada. A registry época 3 existente não
autoriza a ação de emissão. O verificador proposto de bootstrap/owner está
implementado como biblioteca e testado com autoridade sintética, mas não há
configuração nem adapter de runtime protegidos instalados. O preflight do
candidato registra `NOT_INSTALLED`. Conferir assinaturas públicas anteriores
não substitui essa admissão.

Este diretório não fecha a etapa 4 nem publica head/CAS da etapa 5. O ADR aprovado
permanece byte-idêntico; a emenda é entregue como patch para revisão separada.

## Preparar o contrato e a revisão das unidades

```bash
python3.12 -m tools.governance.cli prepare-decomposition-review \
  --legacy-repo /caminho/para/mbras-campaigns \
  --out /diretorio/local/review-bundle.json
```

O comando produz um pacote de propostas: os 116 perfis do ADR, a sequência de
bootstrap/owner proposta e uma análise para cada uma das 122 unidades. O exit 0
confirma a escrita local; o pacote continua não assinável e sem decisões humanas.
Cada unidade inclui seletor/digest, linhas, justificativa, invariantes, testes
planejados e vínculos de helpers/decoradores. A revisão histórica identifica
os destinos compartilhados. O comando abaixo os materializa como seletores v2,
mantendo todos os owners e decisões nulos:

```bash
python3.12 -m tools.governance.cli prepare-decomposition-dispositions \
  --legacy-repo /caminho/para/mbras-campaigns \
  --out /diretorio/local/dispositions.json
```

Use esse arquivo como `--params` do build. Ele contém propostas, não código
de destino nem aprovação humana. São um grupo de retenção e três assemblies.

Leia [ADMISSION-CONTRACT.proposed.md](ADMISSION-CONTRACT.proposed.md) e
[UNIT-REVIEW.proposed.md](UNIT-REVIEW.proposed.md). O resumo por grupo serve
para navegar; o JSON identifica cada unidade pelo inventory_id completo.
Essa revisão propõe disposições; o novo comando cria um arquivo separado.
