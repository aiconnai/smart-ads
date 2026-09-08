# D4 — contrato de admissão proposto

Status: proposta local para ratificação. Não é um perfil instalado, uma registry
emitida ou autorização de assinatura. Base: `d18ac69`; ADR aprovado §12.1/§12.7,
SHA-256 `239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e`.

O fechamento abaixo define como admitir o manifesto; não presume que os
verificadores de runtime já existam. As representações propostas são entregues
em `admission-contract.proposed.json`, geradas pelo comando
`prepare-decomposition-review`. O ADR aprovado e a configuração instalada
permanecem inalterados.

## 1. Inventário fechado de perfis

O contrato contempla **todos os 116 perfis P1** da tabela §12.7, não somente o
manifesto. Cada perfil tem exatamente dez membros não nulos:

| Campo | Regra proposta |
|---|---|
| `schema` | Nome exato com prefixo `smart_ads/`; unicidade e conjunto completo do ADR |
| `digest_json_pointer` | `/integrity/content_digest` |
| `signature_json_pointer` | `/integrity/signature_base64` |
| `preimage_rule` | `P1`, sem alterar a primitiva existente |
| `signer_role` | Papel literal da tabela do ADR |
| `current_revocation_policy` | Expansão explícita de E/H/T/A; não é default do verificador |
| `time_policy` | Objeto fechado `{code, interval_semantics}`, ambos extraídos da tabela |
| `domain_prefix` | String UTF-8 exata da tabela, incluindo o LF explicitamente indicado |
| `semantic_predicate_id` | `adr0001_v19:<schema-sem-prefixo>`; identificador proposto, com requisito normativo associado |
| `dag_slot` | Slot literal da tabela; nenhuma posição inferida do nome do schema |

Os requisitos dos 116 predicados estão no catálogo associado. Seus bindings
executáveis começam nulos: extrair a tabela não implementa esses predicados.
Um schema desconhecido, perfil duplicado, campo extra ou tupla divergente
rejeita a emissão admitida. A lista de perfis não se autoriza a si mesma.

Para o futuro envelope `artifact_contract_inventory/v1`, propõe-se a forma
fechada: `$schema`, `trust_anchor_id`, `epoch`, `issued_at_utc`, `validity`,
`predecessor_inventory_locator`, `profiles`, `integrity`. `epoch` é inteiro
positivo exato; o predecessor é nulo apenas em genesis. `validity` contém
`from`/`until`, UTC estrito, intervalo não vazio. `integrity` usa a forma P1 já
estabelecida, incluindo um único snapshot de registry. O verificador precisa
conferir continuidade, âncora, época, tempo e perfis; o JSON proposto nesta
entrega não é esse envelope.

## 2. Configuração protegida e bootstrap

A configuração atual, com hash
`bda7f38dfe36fc083f11bfa8502bc0d0e458319026c87c893fa86210b901a8ad`, só identifica
a âncora e permite registry. Não contém as tuplas de bootstrap nem a identidade
de um registrador linearizável de head/checkpoint exigidas no ADR.

A futura atualização protegida preserva a identidade pública e acrescenta:

- o tipo `smart_ads/artifact_contract_inventory/v1` à allowlist;
- `inventory_bootstrap_profile`, a tupla completa de dez campos do inventário;
- `anti_rollback_checkpoint_profile`, a tupla completa do checkpoint, com A;
- a identidade protegida da célula e dos registradores de head/checkpoint;
- referência de instalação out-of-band, com bytes/hash completos e autoridade
  de instalação conferidos antes de ler um inventário.

As identidades dos registradores e a prova de instalação dependem da instalação
real; não recebem valores fictícios nem defaults nesta proposta. O inventário
não pode escolher a configuração ou redefinir a tupla A. A instalação é uma
etapa separada: gravar um JSON no repositório não a realiza.

Sequência obrigatória, sem atalhos:

1. Conferir configuração protegida, bytes/hash, instalação e validade.
2. Usar apenas a tupla protegida para verificar provisoriamente P1, forma
   fechada e unicidade do inventário. Nenhuma linha tem autoridade ainda.
3. Verificar checkpoint com a tupla A da configuração e o highest-seen CAS
   protegido, sem consultar estado de chaves que o checkpoint está estabelecendo.
4. Exigir igualdade da linha A do inventário com a tupla protegida; conferir
   head, estado corrente e registry, épocas/digests e toda a cadeia sem forks,
   links ausentes ou rollback. Rejeitar conflito CAS.
5. Completar E do inventário contra essa autoridade corrente.
6. Só então admitir o perfil do manifesto e executar sua validação H.

O relógio autenticado, os limites de idade e o intervalo são aqueles exigidos
no §12.1. Hora local de geração de proposta não substitui esse relógio.
O head de **estado de chaves** é predecessor dessa cadeia; não é o head de
**decomposição**, que continua pertencendo à etapa 5. Preparar e instalar o
bootstrap precisa preceder a emissão final da etapa 4, mesmo que o mapa de
implementação anterior não explicitasse essa dependência.

## 3. Owner, ação e registry

Proposta: `principal:ronaldo`, tenant `mbras`, com uma chave pública dedicada e
papel `decomposition_owner`, vinculado ao papel de perfil `decomposition owner`.
Permissão exata: `(smart_ads/decomposition_manifest/v1, decomposition_manifest_issue)`.

A registry atual só possui a chave humana `gate2_approver` e a chave
`trust_anchor`. Acrescentar uma action não prova compatibilidade de papel.
Uma chave dedicada evita repapelizar as duas entradas existentes ou duplicar
os mesmos bytes sob outro key_id. Nenhuma chave foi criada ou solicitada nesta
entrega; `key_id` fica nulo na proposta até o humano designar a chave pública.

A época 4 é a sucessora proposta da época 3 fixada nesta preparação. As entradas
existentes, suas actions e as épocas antigas são preservadas. Antes de emitir,
revalidar a ponta vigente: se já houver outra época, replanejar a sucessora;
não sobrescrever nem publicar um fork. Validade, unicidade de bytes/hash,
principal, tenant, papel, estado ativo e ação exata são verificações obrigatórias.

Para os artefatos novos da cadeia E, propõem-se ainda três pares exatos na
entrada do anchor, preservando suas actions atuais: `artifact_contract_inventory/v1`
→ `contract_inventory_issue`, `current_key_state/v1` → `current_key_state_issue`
e `current_key_state_head/v1` → `current_key_state_head_issue` (schemas com
prefixo `smart_ads/`). O binding de papel é `external trust anchor` →
`trust_anchor`. O checkpoint A é verificado diretamente pela configuração
protegida; não consulta a registry/estado que está estabelecendo. Esses nomes
de action são propostas novas, não campos supostamente presentes na época 3.

## 4. Manifesto e revisão das decisões

A emenda D1 define o digest semântico antes de adicionar integrity. A admissão
P1 também precisa vincular o perfil, snapshot de registry e identidade do
signer ao run/ADR e às decisões exatas. O builder deve rejeitar owner ausente,
status não resolvido e qualquer alteração do payload após a revisão humana.

O digest do pacote de revisão identifica propostas, não a assinatura humana.
Não existe conversão automática de `decision_status_if_accepted` em
`decision_status`. A aceitação futura deve nomear o digest e as unidades aceitas;
uma mudança de seletor, destino ou invariante exige nova revisão.

Há destinos compartilhados reais nas propostas de segurança: regiões com
decoradores precisam acompanhar suas funções; o histórico preservado aponta
para o mesmo arquivo legado. O draft atual os recusa. O contrato de materialização
deve vincular seletores/assembly disjuntos no destino antes de remover essa
restrição; não se inventam caminhos únicos para fingir que o legado mudou.

## 5. Critérios executáveis para o próximo implementador

O preflight final deve produzir erro antes da semântica downstream para cada
falha nos passos 1–5; não pode aceitar strings `PASS`, flags booleanas ou um
recibo do executor como substitutos das verificações. Testes exigidos:

- configuração apresentada pela requisição; hash ou instalação divergentes;
- inventário autoassinado, domínio errado, linha ausente/extra/duplicada;
- checkpoint A vindo do inventário, linha A divergente ou loop de dependência;
- época menor, mesmo epoch com digest diferente, links saltados, head expirado,
  chave revogada, incerteza desconhecida ou CAS concorrente;
- owner com bytes corretos e papel errado, action ausente, tenant divergente,
  validade encerrada ou snapshot incompatível;
- decisão pendente, assinatura sobre digest anterior, seleção/bytes alterados,
  destino compartilhado não resolvido ou invariantes contraditórios.

Nesta entrega foram implementados o gerador e a validação por recomputação do
**contrato proposto**, não esse verificador de runtime. A saída lista os seis
checks como não implementados e permanece `authority: none`, `signable: false`.
Essa distinção impede que documentação de bootstrap seja consumida como prova
de bootstrap executado. Ratificação do contrato, instalação, emissão e publicação
continuam sendo estados distintos.
