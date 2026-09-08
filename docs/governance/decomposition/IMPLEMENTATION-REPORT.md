# Etapa 4 — implementação local do builder de candidatos

Base: `d18ac69f40693a89a969307661cecbf5e823f780`.
Branch local: `governance/decomposition-step4-plan`.
Escopo autorizado: emenda proposta, implementação e testes locais, sem commit,
assinatura ou publicação. Este relatório não ratifica o contrato nem aprova
decisões de migração.

## Entrega

Os três comandos descritos no [README](README.md) resolvem o inventário Git
pinado, geram inputs revisáveis e constroem/recomputam candidatos offline.
O código separa escopo, seletores, decisões, composição do candidato,
pré-condições históricas e fronteira CLI. Não registra um domínio P1 novo.

A [emenda proposta](ADR-AMENDMENT.proposed.patch) fecha a interpretação local
de D1–D3; `git apply --check` passou. O ADR aprovado não foi alterado: SHA-256
`239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e`.

## Verificação final

| Verificação | Resultado |
|---|---|
| Suíte completa, incluindo os 166 testes anteriores | 224 passed |
| Testes novos de decomposição | 58 passed |
| Runtime efetivo | CPython 3.12.13 |
| Arquivos no escopo real | 44 |
| Unidades selecionadas | 122: 43 whole_file e 79 AST/residuais |
| Decisões e owners pendentes | 122 |
| Resolve / build / verify / rebuild | exit 0 / 0 / 5 / 0 |
| Rebuild do candidato com mesmos inputs/data | byte-idêntico |
| Estado de admissão | INCOMPLETE; signable false |

A suíte foi executada em snapshot isolado com rede, escrita externa e leitura
do home negadas; uma sonda conferiu os três bloqueios. O runner usou CPython
3.12 e apenas as dependências Python de pytest já instaladas em outro venv,
com plugin autoload desabilitado. Não houve instalação. O smoke com o clone
real foi separado desse sandbox, por precisar ler o clone local autorizado;
usou ambiente restrito e os comandos Git offline do resolvedor.

Evidência em `~/Projects/_scratch/smart-ads-step4-PREP/`:
`implementation-final/` contém inputs, candidato, rebuild e resultados CLI;
`implementation-review/` contém os recibos, sondas, testes e hashes do snapshot.
O SHA-256 do candidato final é
`18b5208c096c2651ceb115b471e219895fc43032acace3d5f57b1da880665280`.

## Revisão e correções

A revisão independente inicial encontrou dois achados Medium: tooling podia
ser declarado no core, e um seletor text_region integral contornava a divisão
do arquivo de segurança. O controller reproduziu quatro falhas esperadas antes
dos fixes, com um controle positivo passando. A correção vincula tooling ao
repo/layer correto e exige a partição AST/residual canônica para segurança.

Foram também removidos o owner presumido do template e a aceitação de destinos
compartilhados sem um perfil de target_selector. A segunda revisão independente
conferiu oito contraexemplos e controles positivos, 58 testes e os 17 hashes
do snapshot final, sem novos achados. A suíte completa do controller passou
com 224 testes. Este relatório foi acrescentado depois, somente como síntese
dos recibos; não faz parte dos 17 arquivos da revisão independente.

A revisão usa a skill code-review-rm, intensidade autorizada med. A seleção
de risco xhigh não teve todas as lanes ampliadas executadas: a cobertura
independente é a lane de correção/segurança e o veredito agregado fica limitado
a COMMENT. Os achados aceitos estão fechados; isso não é aprovação formal de
merge, emissão, contrato ou conclusão da etapa 4.

## Limites e próximo trabalho

Este draft não implementa admissão do perfil/owner/bootstrap, correções de
manifesto, sobreposições autorizadas, target_selector ou destino compartilhado.
Recusa essas formas. A partição expõe os bytes para análise, mas não prova a
semântica dos invariantes escritos pelo operador.

Para emitir o manifesto final ainda é necessário fechar e ratificar o contrato
de admissão (D4), implementar seu preflight e revisar as decisões por unidade.
Nenhum dos 122 status foi promovido a approved pelo executor. A assinatura e
publicação só têm um artefato adequado depois desses passos. Não há mudança
de head/CAS da etapa 5, commit, assinatura, push, PR ou merge nesta entrega.
