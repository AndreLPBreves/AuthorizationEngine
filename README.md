# AuthorizationEngine

Protótipo de motor de autorização para avaliar se uma operação pode ser
realizada em determinado contexto. Ele consulta permissões e políticas em
SQLite e combina informações como tenant, unidade operacional, role, IP,
horário e limites de desconto e valor.

O motor foi pensado para ser chamado por uma aplicação maior. Autenticação,
extração de informações de JWT, sanitização e validação das entradas recebidas
do usuário são responsabilidades dessa aplicação.

## Estrutura

```text
src\authorization_engine\engine.py             Motor de autorização
datasets\dbmodel.sqlite                        Esquema SQLite de referência
tests\test_authorization_engine_decisions.py   Testes funcionais
tests\benchmark.py                             Benchmark sequencial e concorrente
requirements.txt                               Dependências Python
```

`datasets\dbmodel.sqlite` contém as tabelas e os índices usados como modelo.
Os testes e o benchmark criam bancos temporários a partir desse esquema e não
alteram o banco de referência.

## Preparação

Requisitos: Python 3.10 ou superior, com suporte às dependências de
`requirements.txt`. O SQLite é acessado pelo módulo `sqlite3` da biblioteca
padrão do Python.

Na raiz do projeto, no PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Com o ambiente virtual ativado, os comandos abaixo usam as dependências
instaladas nele. Execute-os a partir da raiz do projeto.

## Como usar o motor

Chame `AuthorizationEngine.evaluate` com o caminho de um banco SQLite
**populado**, compatível com `datasets\dbmodel.sqlite`. O banco de referência
contém apenas o esquema; usá-lo diretamente não fornece permissões nem
políticas de exemplo.

```python
from src.authorization_engine.engine import AuthorizationEngine

resultado = AuthorizationEngine.evaluate(
    dataset_path=r"C:\caminho\para\autorizacao.sqlite",
    permission="sales:create",
    user_id=1,
    tenant_id=1,
    operational_unit_id=None,
    ip="127.0.0.1",
    requested_discount=10.0,
    requested_amount=500.0,
)

permitido, motivo = resultado
print(permitido, motivo)
```

O retorno normal é `(bool, str)`: a decisão e uma mensagem explicando a
concessão ou negação. Os valores do exemplo devem corresponder aos dados e às
políticas cadastradas no banco.

Os parâmetros `operational_unit_id`, `requested_discount`, `requested_amount`,
`target_user_association_id` e `target_role_id` dependem do contexto da
operação. O parâmetro `ip` é obrigatório na assinatura de `evaluate` e deve ser
informado em todas as chamadas; o motor nega acesso se receber um IP vazio.
Se uma política aplicável limitar desconto ou valor, e nenhuma política
sobrevivente deixar a respectiva dimensão ilimitada, o valor solicitado
correspondente é obrigatório.

Com `enable_benchmark=True`, uma avaliação concedida retorna
`(True, mensagem, tempos)`, com tempos em milissegundos. Avaliações negadas
continuam retornando somente `(False, mensagem)`.

## Regras avaliadas

1. A permissão deve estar atribuída a uma role do usuário no tenant e no
   escopo consultados; também deve haver uma política para a permissão no
   tenant. `operational_unit_id=None` consulta associações globais; uma unidade
   informada consulta somente associações dessa unidade.
2. Para permissões iniciadas por `user_association:` ou `role:`, quando o
   respectivo ID do alvo é informado, são aplicadas verificações administrativas
   de escopo global e de autoalteração. Na alteração de associação, o alvo
   deve estar no mesmo tenant e ter nível de restrição menor que o nível
   considerado para o ator.
3. As políticas são desserializadas e filtradas por IP, roles e horário, nessa
   ordem. O campo `roles` restringe a política às roles encontradas para o
   usuário naquela consulta. Janelas de horário incluem início e fim e podem
   atravessar a meia-noite; o horário usado é o relógio local do processo.
4. Os limites são calculados sobre as políticas que sobreviveram aos filtros.
   Sem política sobrevivente, ou com limite excedido, o acesso é negado.
   JSON malformado e campos de política desconhecidos são exemplos de
   configurações que retornam uma negação por política inválida.

### Particularidades da implementação atual

- Se alguma política tiver whitelist não vazia, somente políticas com o IP
  nessa whitelist permanecem, e as blacklists não são aplicadas nesse ramo.
  Caso contrário, cada política com o IP na sua blacklist é removida.
- Para desconto e valor, o motor usa o maior limite de cada dimensão entre as
  políticas restantes. Os dois limites podem vir de políticas diferentes;
  uma política sem limite para determinada dimensão a torna ilimitada.
- Na hierarquia de associações, é usado o menor `restriction_level` entre
  os vínculos administrativos globais encontrados; o alvo deve ter nível
  estritamente menor. As verificações administrativas específicas só são
  executadas quando o respectivo ID do alvo é fornecido.
- Os testes descrevem os cenários implementados, mas não garantem que essas
  decisões sejam adequadas para toda aplicação. As regras devem ser revisadas
  conforme os requisitos do projeto que integrará o motor.

## Testes funcionais

Para executar todos os testes de decisão:

```powershell
python -m unittest discover -s tests -v
```

A suíte usa `unittest` e verifica casos de concessão e negação envolvendo
escopo, IP, horário, roles, limites, políticas inválidas e operações
administrativas. Cada caso utiliza um banco SQLite temporário; os testes de
horário controlam o relógio para não depender da hora de execução.

## Benchmark

O benchmark chama o motor diretamente, sem servidor HTTP ou rede. Ele cria um
banco temporário com o esquema e os índices de `datasets\dbmodel.sqlite`,
popula dados sintéticos (incluindo ruído de fundo realista nas tabelas de
associação e políticas) e imprime os resultados no terminal. Não modifica o
banco de referência nem salva um relatório automaticamente.

Para uma execução rápida, com volume 1, 100 avaliações sequenciais e 100
avaliações em cada configuração de concorrência:

```powershell
python -c "import runpy; b = runpy.run_path(r'tests\benchmark.py'); b['rodar_benchmark_sequencial'](iteracoes=100, volume=1); b['rodar_benchmark_multithread'](total_ops=100, max_workers_list=[1, 2, 4], volume=1)"
```

Altere `volume` para controlar o tamanho dos dados sintéticos gerados,
`iteracoes` para controlar as avaliações sequenciais, `total_ops` para as
avaliações por configuração concorrente e `max_workers_list` para definir
as quantidades de threads. Use valores inteiros positivos para volume e
quantidades de operações. O volume de cada modalidade é independente.

Para executar a carga definida no final de `tests\benchmark.py`:

```powershell
python -m tests.benchmark
```

**A carga definida no script é grande:** usa `volume=10`, 100.000 avaliações
sequenciais após 200 de aquecimento e 100.000 avaliações para cada
configuração concorrente com 1, 2, 4, 8, 16 e 32 threads. Ajuste os argumentos
na chamada rápida ou no script conforme os recursos disponíveis.

Para um volume inteiro positivo `v`, cada base temporária contém:

| Tabela | Quantidade aproximada |
| --- | --- |
| `tenants` | Maior entre 50 e `10 × v` |
| `users` | `500 × v` |
| `roles` | 5 por tenant |
| `permissions` | 10 |
| `role_permissions` | 10 por role |
| `user_associations` | 10 cenários de teste + massa de fundo (ruído) proporcional ao volume |
| `permission_policies` | 10 cenários de teste + massa de fundo (ruído) proporcional ao volume |

Por exemplo, `volume=10` gera mais de 50 tenants, 5.000 usuários e popula as
tabelas principais com massa de fundo para testar o comportamento do índice e
da árvore B-Tree do banco sob carga realista.

São gerados dez contextos que variam tenant, permissão, desconto e valor;
cada avaliação seleciona um deles aleatoriamente, sem semente fixa. Os
contextos usam o mesmo usuário e IP e foram configurados para concessão.
As bases para os testes sequencial e concorrente são criadas separadamente.

O relatório sequencial apresenta tempos por etapa e total, em milissegundos:
média, mediana, P95, P99, mínimo, máximo e desvio padrão. A vazão sequencial é
uma estimativa calculada a partir da média do tempo total. O relatório
concorrente apresenta latências por avaliação, tempo decorrido e avaliações
por segundo calculadas sobre o tempo total, incluindo a execução com
`ThreadPoolExecutor`.

Para interpretar os resultados no TCC, registre o ambiente de execução:

- **Processador:** AMD Ryzen 5 1400 (com overclock a 3,7 GHz)
- **Memória RAM:** 16 GB DDR4 a 2.666 MHz
- **Armazenamento:** SSD SATA MCR-BM400-480
- **Sistema operacional:** Windows 10 (Build 19045.6466) em modo de alto desempenho
- **Interpretador:** Python 3.15.2

O benchmark usa dez contextos sintéticos de acesso concedido e não simula
tráfego HTTP, distribuição de requisições reais ou diferentes cenários de
negação. Nas associações geradas, a role associada nem sempre pertence ao
mesmo tenant segundo a tabela `roles`; portanto, a massa não representa
necessariamente relações consistentes de uma aplicação real.

As métricas internas só são retornadas em avaliações concedidas: o benchmark
sequencial não coleta nem contabiliza decisões negadas, apesar do contador
de recusas exibido; se nenhuma avaliação retornar métricas, o cálculo da média
falha. O concorrente registra tempo zero para negações, sem contabilizá-las
separadamente. Confirme as decisões dos contextos e revise essas limitações
antes de usar os números como evidência de performance geral.
