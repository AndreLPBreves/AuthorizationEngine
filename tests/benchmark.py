import json
import random
import sqlite3
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from src.authorization_engine.engine import AuthorizationEngine

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DATABASE = ROOT / "datasets" / "dbmodel.sqlite"

def setup_benchmark_db(volume: int = 1):
    directory = tempfile.TemporaryDirectory()
    db_path = str(Path(directory.name) / "benchmark.sqlite")

    with closing(sqlite3.connect(SCHEMA_DATABASE.resolve().as_uri() + "?mode=ro", uri=True)) as source:
        schema_items = source.execute("""
            SELECT sql FROM sqlite_master
            WHERE type in ('table', 'index') AND name NOT LIKE 'sqlite_%'
            ORDER BY type DESC, name
        """).fetchall()

    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA synchronous = NORMAL")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA busy_timeout = 5000")

        for (sql,) in schema_items:
            db.execute(sql)

        qtd_tenants = max(50, volume * 10) + 1
        # 1. Inserir massa de Tenants baseada no volume
        tenants_data = [(i, f"Tenant SaaS {i}") for i in range(1, qtd_tenants)]
        db.executemany("INSERT INTO tenants (tenant_id, name) VALUES (?, ?)", tenants_data)

        # 2. Inserir massa de Users
        users_data = [(i, f"Usuário Simulado {i}") for i in range(2, volume * 500 + 1)]
        db.executemany("INSERT INTO users (user_id, name) VALUES (?, ?)", users_data)
        db.execute("INSERT OR IGNORE INTO users (user_id, name) VALUES (1, 'André Breves')")

        # 3. Inserir massa de Roles (5 cargos por tenant)
        roles_data = []
        role_id_counter = 1
        for t_id in range(1, qtd_tenants):
            for _ in range(5):
                roles_data.append((role_id_counter, t_id, f"Cargo {role_id_counter}"))
                role_id_counter += 1
        db.executemany("INSERT INTO roles (role_id, tenant_id, name) VALUES (?, ?, ?)", roles_data)

        # 4. Permissões variadas para os 10 cenários
        permissions_data = [
            (1, 'sales:create'),
            (2, 'sales:update'),
            (3, 'sales:delete'),
            (4, 'reports:view'),
            (5, 'reports:export'),
            (6, 'users:manage'),
            (7, 'settings:update'),
            (8, 'audit:view'),
            (9, 'inventory:read'),
            (10, 'inventory:write')
        ]
        db.executemany("INSERT OR IGNORE INTO permissions (permission_id, permission_code) VALUES (?, ?)", permissions_data)

        rp_data = [(r_id, p_id) for r_id in range(1, role_id_counter) for p_id in range(1, 11)]
        db.executemany("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", rp_data)

        # 5. Associações para os 10 cenários (user_id=1 associado aos 10 tenants de teste)
        assoc_data = []
        for i in range(1, 11):
            assoc_data.append((i, 1, i, None, i, i * 10))

        # [INCLUSÃO] Massa de fundo (ruído) em user_associations para simular carga real de banco
        assoc_id_counter = 11
        for u_id in range(2, volume * 500 + 1):
            for t_id in range(1, qtd_tenants):
                if random.random() < 0.05:  # 5% de chance por combinação para gerar massa sem excessos injivíveis
                    valid_role_id = random.randint((t_id - 1) * 5 + 1, min(t_id * 5, role_id_counter - 1))
                    assoc_data.append((assoc_id_counter, u_id, t_id, None, valid_role_id, 10))
                    assoc_id_counter += 1

        db.executemany("""
            INSERT INTO user_associations (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (?, ?, ?, ?, ?, ?)
        """, assoc_data)

        # 6. Políticas de Segurança para os 10 cenários e massa de fundo
        rules_base = {
            "ip_whitelist": ["127.0.0.1", "192.168.1.50"],
            "time_window": {"start_time": "00:00", "end_time": "23:59"},
            "max_discount": 20.0,
            "max_amount": 1000.0
        }

        policies_data = []
        for i in range(1, 11):
            r = rules_base.copy()
            r["roles"] = [i]
            policies_data.append((i, i, json.dumps(r)))

        # [INCLUSÃO] Massa de fundo em permission_policies para outros tenants
        for p_id in range(1, 11):
            for t_id in range(1, qtd_tenants):
                if t_id > 10 and random.random() < 0.15:
                    policies_data.append((p_id, t_id, json.dumps(rules_base)))

        db.executemany("""
            INSERT OR REPLACE INTO permission_policies (permission_id, tenant_id, rules)
            VALUES (?, ?, ?)
        """, policies_data)

    return directory, db_path

def calcular_estatisticas(tempos):
    if not tempos:
        return {"min": 0, "media": 0, "mediana": 0, "p95": 0, "p99": 0, "max": 0, "std": 0}

    tempos_ord = sorted(tempos)
    total = len(tempos)

    try:
        quantis_100 = statistics.quantiles(tempos, n=100, method='inclusive')
        p95_val = quantis_100[94]
        p99_val = quantis_100[98]
    except (statistics.StatisticsError, IndexError):
        p95_val = tempos_ord[int(total * 0.95)]
        p99_val = tempos_ord[int(total * 0.99)]

    return {
        "min": tempos_ord[0],
        "media": statistics.mean(tempos),
        "mediana": statistics.median(tempos),
        "p95": p95_val,
        "p99": p99_val,
        "max": tempos_ord[-1],
        "std": statistics.stdev(tempos) if total > 1 else 0.0
    }

def gerar_cenarios(db_path):
    codigos_perm = [
        'sales:create', 'sales:update', 'sales:delete',
        'reports:view', 'reports:export', 'users:manage',
        'settings:update', 'audit:view', 'inventory:read', 'inventory:write'
    ]

    cenarios = []
    for i in range(1, 11):
        cenarios.append({
            "dataset_path": db_path,
            "permission": codigos_perm[i - 1],
            "user_id": 1,
            "tenant_id": i,
            "ip": "127.0.0.1",
            "requested_discount": float(i * 2),
            "requested_amount": float(i * 100),
            "enable_benchmark": True
        })
    return cenarios

def rodar_benchmark_sequencial(iteracoes=100000, volume=10):
    directory, db_path = setup_benchmark_db(volume=volume)
    cenarios = gerar_cenarios(db_path)

    for _ in range(200):
        AuthorizationEngine.evaluate(**random.choice(cenarios))

    metricas_coletadas = {
        "db_lookup_ms": [],
        "pydantic_deserialization_ms": [],
        "filter_ip_ms": [],
        "filter_roles_ms": [],
        "filter_time_ms": [],
        "validate_limits_ms": [],
        "total_evaluate_ms": []
    }

    cenarios_avaliados = 0
    sucessos = 0
    falhas = 0

    for _ in range(iteracoes):
        contexto_atual = random.choice(cenarios)
        resultado = AuthorizationEngine.evaluate(**contexto_atual)
        if len(resultado) == 3:
            resultado, _, tempos = resultado

            cenarios_avaliados += 1
            if resultado:
                sucessos += 1
            else:
                falhas += 1
            for chave in metricas_coletadas:
                if chave in tempos:
                    metricas_coletadas[chave].append(tempos[chave])

    print("=" * 105)
    print(f"  RELATÓRIO VOLUMETRIA ALTA (SEQUENCIAL) - 10 CENÁRIOS - ({cenarios_avaliados} cenarios. concedido {sucessos}/{falhas} recusado)")
    print("=" * 105)
    print(f"{'Etapa do Pipeline':<30} | {'Média':<8} | {'Mediana':<8} | {'P95':<8} | {'P99':<8} | {'Min':<8} | {'Max':<8} | {'DesvioPad':<8}")
    print("-" * 105)

    nomes_amigaveis = {
        "db_lookup_ms": "1. Consulta SQL (DB Lookup)",
        "pydantic_deserialization_ms": "2. Desserialização Pydantic",
        "filter_ip_ms": "3. Filtro de IP",
        "filter_roles_ms": "4. Filtro de Roles",
        "filter_time_ms": "5. Filtro de Janela de Tempo",
        "validate_limits_ms": "6. Validação de Limites",
        "total_evaluate_ms": "7. PIPELINE COMPLETO (Total)"
    }

    for chave, nome in nomes_amigaveis.items():
        st = calcular_estatisticas(metricas_coletadas[chave])
        print(f"{nome:<30} | {st['media']:<8.4f} | {st['mediana']:<8.4f} | {st['p95']:<8.4f} | {st['p99']:<8.4f} | {st['min']:<8.4f} | {st['max']:<8.4f} | {st['std']:<8.4f}")

    print("=" * 105)
    media_total = statistics.mean(metricas_coletadas["total_evaluate_ms"])
    rps = (1000 / media_total) if media_total > 0 else 0
    print(f"VAZÃO ESTIMADA (Single-Thread): ~{rps:.2f} avaliações/segundo (RPS)")
    print("=" * 105)

    directory.cleanup()
    return db_path

def rodar_benchmark_multithread(total_ops=100000, max_workers_list=None, volume=10):
    if max_workers_list is None:
        max_workers_list = [1, 2, 4, 8, 16, 32]
    directory, db_path = setup_benchmark_db(volume=volume)
    cenarios = gerar_cenarios(db_path)

    print("\n" + "=" * 125)
    print(f"  BENCHMARK CONCORRENTE VOLUMETRIA ALTA - 10 CENÁRIOS - VOLUME: {volume} - ({total_ops} ops)")
    print("=" * 125)
    print(f"{'Threads':<8} | {'Tempo (s)':<10} | {'RPS Real':<12} | {'Média (ms)':<10} | {'Mediana':<10} | {'P95 (ms)':<10} | {'P99 (ms)':<10} | {'Min (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 125)

    for workers in max_workers_list:
        metricas = []

        def worker_task():
            ctx = random.choice(cenarios)
            res = AuthorizationEngine.evaluate(**ctx)
            if len(res) == 3:
                return res[2].get("total_evaluate_ms", 0.0)
            return 0.0

        t_inicio = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(worker_task) for _ in range(total_ops)]
            for future in futures:
                metricas.append(future.result())
        t_fim = time.perf_counter()

        tempo_total = t_fim - t_inicio
        rps_real = total_ops / tempo_total
        st = calcular_estatisticas(metricas)

        print(f"{workers:<8} | {tempo_total:<10.4f} | {rps_real:<12.2f} | {st['media']:<10.4f} | {st['mediana']:<10.4f} | {st['p95']:<10.4f} | {st['p99']:<10.4f} | {st['min']:<10.4f} | {st['max']:<10.4f}")

    print("=" * 125)
    directory.cleanup()

if __name__ == "__main__":
    rodar_benchmark_sequencial(iteracoes=100000, volume=10)
    rodar_benchmark_multithread(total_ops=100000, max_workers_list=[1, 2, 4, 8, 16, 32], volume=10)
