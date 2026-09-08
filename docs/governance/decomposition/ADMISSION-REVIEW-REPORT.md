# Continuação da etapa 4 — contrato e revisão das unidades

Base Git preservada: `d18ac69f40693a89a969307661cecbf5e823f780`.
Branch local: `governance/decomposition-step4-plan`. Sem commit.
Escopo desta continuação: especificar o contrato de admissão e preparar a
revisão das 122 unidades para o manifesto final. Propostas não são ratificação,
assinatura ou aceitação humana das decisões.

## Entregas

- [Contrato D4](ADMISSION-CONTRACT.proposed.md) e
  [catálogo de dados](admission-contract.proposed.json): 116 perfis, seis passos
  de bootstrap/admissão, owner/papel/action propostos e dependências de instalação.
- [Revisão navegável](UNIT-REVIEW.proposed.md) e
  [propostas completas](unit-review.proposed.json): uma entrada por inventory_id,
  com fontes/digests, linhas, justificativa, invariantes, testes e vínculos locais.
- Comando `prepare-decomposition-review`, com saída local atômica, e validadores
  que recomputam os dados. Não há comando que aceite as propostas como humanas.

| Disposição proposta | Unidades |
|---|---:|
| Permanecer sob governança legada | 37 |
| Tooling de repositório | 7 |
| Reimplementação limpa do conductor | 1 |
| Separação por invariante de segurança | 19 |
| Diferir Pinna / Google / funnel | 18 / 5 / 3 |
| Referência de whitespace, sem implementação | 32 |
| **Total** | **122** |

Há 27 referências diretas a helpers locais e sete vínculos de decorador/corpus
com a função seguinte. A busca de referências é estática e limitada aos bytes
de cada unidade; não prova resolução dinâmica nem fecho transitivo de imports.
Arquivos inteiros foram classificados pela disposição do ADR, nomes/imports e
identidade Git; esta não é uma auditoria linha a linha dos sistemas legados.

Quatro grupos compartilham destino: histórico no mesmo arquivo legado e pares
decorador/função. Eles estão expostos no JSON/Markdown, sem renomear o legado
artificialmente. A materialização exige o contrato final de target_selector ou
assembly; o builder de candidatos continua recusando esses compartilhamentos.

## Verificação e revisão independente

- Suíte completa em snapshot isolado, CPython 3.12.13: **250 passed**, contra
  os 224 da entrega anterior. Os 26 testes novos verificam propostas/recusas,
  não uma admissão de runtime fictícia.
- CLI real: dois pacotes reconstruídos byte a byte iguais, iguais aos JSONs
  locais de revisão. O candidato anterior continua INCOMPLETE, exit 5.
- SHA-256 do pacote final de revisão:
  `561cac4ae6f3d34e1368fe4427cef95458494267d2711629c536b62b51f276de`.
- Um achado Medium aceito: o template pendente não aplicava as restrições finais
  de destino a uma proposta diferida. O controller também encontrou o problema
  durante a revisão. Foram fixados repo/layer/ausência de target para diferidos
  e a retenção da localização original para governança legada.
- Quatro contraexemplos falharam por DID NOT RAISE no snapshot anterior ao fix.
  A segunda revisão independente confirmou 26 testes, 16 contraexemplos
  recusados, 12 hashes e recomputação dos JSONs/Markdown, sem novos achados.

Skill code-review-rm: requested/authorized med, selected xhigh pelo domínio de
contrato; lanes ampliadas não executadas. Revisão do controller e verificador
independente cobrem os 12 caminhos do delta contra o snapshot da entrega anterior.
Achieved med, status partial quanto à seleção xhigh, veredito agregado COMMENT;
não constitui aprovação formal de publicação, contrato ou emissão.
Este relatório é a síntese posterior aos recibos, fora desses 12 caminhos.

Evidências em `~/Projects/_scratch/smart-ads-step4-PREP/`: execução final em
`admission-review-final/`, recibos e snapshots dos arquivos alterados em
`admission-review-evidence/`. A execução inicial é preservada separadamente;
apenas o pacote final contém as clarificações finais de D4.

## Estado que permanece explícito

Os 122 campos human_decision/system_owner continuam nulos. As propostas
`decision_status_if_accepted` não foram copiadas para o manifesto. Os testes
citados nas decisões são trabalho futuro ou referência legada; nenhum teste
legado ou código de provedor foi executado.

O ADR e a configuração protegida permanecem byte-idênticos. A registry época 3
e os nove objetos existentes não foram alterados. Nenhuma chave privada do
operador foi acessada ou usada; não houve assinatura real, instalação protegida,
publicação ou mudança de head/CAS. A suíte preexistente usa chaves efêmeras de
teste, isoladas do material de assinatura humano.

O contrato proposto está especificado para revisão; o verificador real da
cadeia de bootstrap/admissão continua não implementado, com seis checks
explicitamente listados nessa condição. Esse trabalho, a ratificação/instalação aplicável,
a resolução dos destinos compartilhados e a aceitação humana das disposições
precedem a emissão do manifesto final. A etapa 4 não está encerrada por esta
entrega de preparação.
