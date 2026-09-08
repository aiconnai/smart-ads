# Etapa 4 — runtime proposto e destinos v2

Implementação concluída no escopo autorizado; etapa 4 ainda não admitida.
Preparada na branch `governance/decomposition-step4-plan`, sobre a época 4 da
registry já integrada em `main`.

## Entrega

- Verificador dos seis checks D4 com P1, perfis exatos, registros históricos,
  cadeia atual, relógio autenticado e protocolo de CAS protegido.
- Retenção exata de 28 unidades no destino legado e três assemblies de dois
  membros (decorador/definição), sem alegar que o código de destino já existe.
- CLI `prepare-decomposition-dispositions`; compatibilidade de verificação v1.
- Suíte completa: **316 passed**. Revisão independente final: **66 passed**,
  quatro contraexemplos recusados e caso positivo de remoção de ação irrelevante.
- Candidato real: **44 caminhos, 122 unidades, 122 owners e decisões pendentes**.
  Build/rebuild byte-idênticos; verify v2 e candidato histórico v1: exit 5,
  recomputação válida, INCOMPLETE, NOT_INSTALLED, signable false.

## Digests exatos

| Artefato | SHA-256 |
|---|---|
| RUNTIME-CONTRACT.proposed.md | `sha256:d260537bcccb37ef4eb61db09aab2258229fc580e1292e0dd98b9b1406c5da25` |
| dispositions.json completo | `sha256:7a9d936346ec6b81a45046912fe66bdae70711fbc769d9019e9203c12c6ed5b9` |
| candidate.json completo | `sha256:fa72bb96486ea86e7a890e0d58ba7e2ed30605642dc117f614cd60fb4415d52d` |
| payload do candidato | `sha256:91973342807877fa03bd13bab8cb8fb4e9400a26ca257d9694c14f5e5f5da43e` |

Os digests de arquivo completo e payload são distintos. Nenhum é tratado como
assinatura, locator de envelope admitido ou aprovação humana.

## Revisão e correção

O primeiro review demonstrou head avançando de época 1 para 2 durante a leitura
final do relógio, com VERIFIED indevido da época 1. O controller reproduziu.
Também foi reproduzida a permanência de VERIFIED após retirada da ação do
owner no registro atual. A política escolhida foi explicitada no contrato:
exigir atualmente apenas as ações utilizadas pelos seis checks.

A correção termina todas as leituras/assinaturas antes de uma observação
coerente de head+relógio, seguida apenas de comparações puras. Head avançado,
expiração e retirada da ação rejeitam. O piso já avançado pelo CAS é preservado.
Os três novos testes falham por DID NOT RAISE no snapshot inicial e passam no
final. Uma execução comparativa sem importlib importou o código final por
engano; foi descartada e repetida com --import-mode=importlib.

**Revisão:** requested med; selected xhigh por risco; achieved med; partial;
veredito formal COMMENT. Os 11 caminhos de implementação/testes/contrato foram
cobertos e seus hashes reconciliados. Não houve novos achados na segunda
passada. A revisão ampliada xhigh não foi executada nem alegada. Este relatório
é um artefato derivado, conferido pelo controller contra os recibos.

## Limites que permanecem

O runtime protegido é uma interface de integração, sem adapter de produção
instalado. CAS e observação coerente foram exercitados apenas no runtime
sintético com chaves efêmeras. As garantias de linearização e tempo precisam
ser satisfeitas por uma implementação protegida antes de admissão real.
O argumento SourceSnapshot da biblioteca é confiável e deve vir de
resolve_scope; não pode ser montado a partir de dados de uma requisição.
O teste criptográfico positivo usa fonte/autoridade sintéticas; a resolução e
recomputação real das 122 unidades são evidência separada, sem assinatura.

Os 116 perfis são conferidos; somente os seis predicados desta entrega estão
implementados. Correções imutáveis de manifesto continuam recusadas. Faltam
ratificação do contrato, revisão das 122 disposições, vínculo público do owner,
registry apropriada, instalação protegida e os artefatos assinados reais.

ADR, configuração protegida, P1 e os nove objetos do store permanecem idênticos.
Nenhuma chave do operador, assinatura do anchor real, CAS real, commit, push,
PR, merge ou chamada à Meta foi utilizado/executado.

Evidências em `runtime-implementation-evidence/`; artefatos finais em
`runtime-implementation-final/`, ambos no diretório de preparação.
