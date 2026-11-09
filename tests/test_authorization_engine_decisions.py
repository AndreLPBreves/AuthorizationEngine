import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from src.authorization_engine.engine import AuthorizationEngine

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DATABASE = ROOT/"datasets"/"dbmodel.sqlite"


class TestAuthorizationEngineDecisions(unittest.TestCase):

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.mockDataset = str(Path(self.directory.name)/"test2.sqlite")

        with closing(sqlite3.connect(SCHEMA_DATABASE.resolve().as_uri() + "?mode=ro", uri=True)) as source:
            sourceDBItems = source.execute("""
                SELECT
                    sql
                FROM
                    sqlite_master
                WHERE type in ('table', 'index')
                AND name NOT LIKE 'sqlite_%'
                ORDER BY type DESC, name
            """).fetchall()

        with closing(sqlite3.connect(self.mockDataset)) as db, db:
            db.execute("PRAGMA foreign_keys = ON")
            for (sql,) in sourceDBItems:
                db.execute(sql)

    def execute(self, sql, parameters=()):
        with closing(sqlite3.connect(self.mockDataset)) as db, db:
            db.execute(sql, parameters)


    def execute_many(self, sql, parameters: list[dict]):
        with closing(sqlite3.connect(self.mockDataset)) as db, db:
            db.executemany(sql, parameters)

    def grant(self, role_id, permission_code):
        self.execute("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT ?, permission_id FROM permissions WHERE permission_code = ?
            """,
            (role_id, permission_code)
        )

    def set_policies(self, permission_code, *rules, tenant_id=1):
        with closing(sqlite3.connect(self.mockDataset)) as db, db:
            db.execute("PRAGMA foreign_keys = ON")

            db.execute(
                """
                DELETE FROM permission_policies
                WHERE tenant_id = ? AND permission_id = (
                    SELECT permission_id FROM permissions WHERE permission_code = ?
                )
                """,
                (tenant_id, permission_code)
            )

            for rule in rules:
                db.execute(
                    """
                    INSERT INTO permission_policies (permission_id, tenant_id, rules)
                    SELECT permission_id, ?, ? FROM permissions WHERE permission_code = ?
                    """,
                    (tenant_id, json.dumps(rule), permission_code)
                )

    def evaluate(self, permission="sales:create", **overrides):
        context = {
            "dataset_path": self.mockDataset,
            "permission": permission,
            "user_id": 1,
            "tenant_id": 1,
            "ip": "127.0.0.1",
        }
        context.update(overrides)
        return AuthorizationEngine.evaluate(**context)

    def evaluate_at_time(self, hour, minute, permission="sales:create", **overrides):
            with patch("src.authorization_engine.engine.datetime") as clock:
                clock.now.return_value = datetime(2026, 1, 1, hour, minute)
                return self.evaluate(permission=permission, **overrides)

    def assert_decision(self, result, allowed_esperado, subtexto_motivo):
        allowed, reason = result
        self.assertIs(allowed, allowed_esperado, f"Esperado allowed={allowed_esperado}, mas veio {allowed}. Motivo: {reason}")
        self.assertIn(subtexto_motivo, reason, f"O motivo '{reason}' deveria conter o texto '{subtexto_motivo}'")

class TestesDeIP(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_permitir_ip_na_whitelist(self):
        self.set_policies("sales:create", {"ip_whitelist": ["192.168.1.10"]})
        resultado = self.evaluate(permission="sales:create", ip="192.168.1.10")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_ip_fora_da_whitelist(self):
        self.set_policies("sales:create", {"ip_whitelist": ["192.168.1.10"]})
        resultado = self.evaluate(permission="sales:create", ip="127.0.0.1")
        self.assert_decision(resultado, False, "bloqueado pelas regras de IP")

    def test_barrar_ip_na_blacklist(self):
        self.set_policies("sales:create", {"ip_blacklist": ["192.168.1.10"]})
        resultado = self.evaluate(permission="sales:create", ip="192.168.1.10")
        self.assert_decision(resultado, False, "bloqueado pelas regras de IP")

    def test_permitir_ip_fora_da_blacklist(self):
        self.set_policies("sales:create", {"ip_blacklist": ["192.168.1.20"]})
        resultado = self.evaluate(permission="sales:create", ip="192.168.1.10")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_whitelist_tem_prioridade_sobre_blacklist(self):
        self.set_policies("sales:create", {"ip_whitelist": ["192.168.1.20"], "ip_blacklist": ["192.168.1.20"]})
        resultado = self.evaluate(permission="sales:create", ip="192.168.1.20")
        self.assert_decision(resultado, True, "Acesso Concedido")

class TestedDeJanelaDeTempo(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_permitir_apenas_dentro_do_horario_estipulado(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "08:00", "end_time": "18:00"}})
        resultado = self.evaluate_at_time(hour=14, minute=30, permission="sales:create")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_fora_da_janela_de_horario(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "08:00", "end_time": "18:00"}})
        resultado = self.evaluate_at_time(hour=22, minute=0, permission="sales:create")
        self.assert_decision(resultado, False, "fora da janela de horário permitida")

    def test_fronteiras_da_janela_sao_inclusivas(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "09:00", "end_time": "17:00"}})
        self.assert_decision(self.evaluate_at_time(8, 59, permission="sales:create"), False, "fora da janela")
        self.assert_decision(self.evaluate_at_time(9, 0, permission="sales:create"), True, "Acesso Concedido")
        self.assert_decision(self.evaluate_at_time(17, 0, permission="sales:create"), True, "Acesso Concedido")
        self.assert_decision(self.evaluate_at_time(17, 1, permission="sales:create"), False, "fora da janela")


class TestesDeLimites(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_permitir_desconto_dentro_do_limite(self):
        self.set_policies("sales:create", {"max_discount": 20.0})
        resultado = self.evaluate(permission="sales:create", requested_discount=15.0)
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_desconto_acima_do_limite(self):
        self.set_policies("sales:create", {"max_discount": 20.0})
        resultado = self.evaluate(permission="sales:create", requested_discount=25.0)
        self.assert_decision(resultado, False, "excede o limite máximo permitido")

    def test_permitir_valor_monetario_dentro_do_limite(self):
        self.set_policies("sales:create", {"max_amount": 1000.0})
        resultado = self.evaluate(permission="sales:create", requested_amount=500.0)
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_valor_monetario_acima_do_limite(self):
        self.set_policies("sales:create", {"max_amount": 1000.0})
        resultado = self.evaluate(permission="sales:create", requested_amount=1500.0)
        self.assert_decision(resultado, False, "excede o limite máximo permitido")


class TestesDeGovernancaEHIerarquia(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO users (user_id, name) VALUES (2, 'Outro Usuário')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (2, 1, 'Admin Global')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'user_association:update')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (2, 'role:update')")
        self.grant(2, 'user_association:update')
        self.grant(2, 'role:update')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 2, 50)
        """)
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (2, 2, 1, NULL, 1, 30)
        """)
        self.execute("""
            INSERT INTO permission_policies
            (permission_policy_id, permission_id, tenant_id, rules)
            VALUES (1, 1, 1, '{}')
        """)
        self.execute("""
            INSERT INTO permission_policies
            (permission_policy_id, permission_id, tenant_id, rules)
            VALUES (2, 2, 1, '{}')
        """)

    def test_barrar_usuario_modificando_propria_associacao(self):
        resultado = self.evaluate(
            permission="user_association:update",
            target_user_association_id=1
        )
        self.assert_decision(resultado, False, "Usuários não podem modificar suas próprias associações")

    def test_barrar_usuario_modificando_propria_role(self):
        resultado = self.evaluate(
            permission="role:update",
            target_role_id=2
        )
        self.assert_decision(resultado, False, "Usuários não podem modificar permissões ou propriedades da role que eles próprios possuem")

    def test_barrar_hierarquia_insuficiente(self):
        self.execute("""
            UPDATE user_associations SET restriction_level = 50 WHERE user_association_id = 2
        """)
        resultado = self.evaluate(
            permission="user_association:update",
            target_user_association_id=2
        )
        self.assert_decision(resultado, False, "nível restritivo global")


class TestesDeEscopoTenantEUnidade(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (2, 'Tenant Beta')")
        self.execute("INSERT INTO operational_units (operational_unit_id, tenant_id, name) VALUES (1, 1, 'Unidade Alpha 1')")
        self.execute("INSERT INTO operational_units (operational_unit_id, tenant_id, name) VALUES (2, 2, 'Unidade Beta 1')")

        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador Alpha')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')

        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, 1, 1, 50)
        """)

    def test_barrar_acesso_a_outro_tenant(self):
        self.set_policies("sales:create", {}, tenant_id=2)
        resultado = self.evaluate(permission="sales:create", tenant_id=2)
        self.assert_decision(resultado, False, "não possui a permissão")

    def test_permitir_acesso_ao_tenant_e_unidade(self):
        self.set_policies("sales:create", {})
        resultado = self.evaluate(permission="sales:create", operational_unit_id=1)
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_acesso_tenant_certo_unidade_errada(self):
        self.set_policies("sales:create", {})
        resultado = self.evaluate(permission="sales:create", operational_unit_id=2)
        self.assert_decision(resultado, False, "não possui a permissão")


class TestesDeMultiplasPoliticasELimites(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_multiplas_politicas_usam_maior_limite_sobrevivente(self):
        self.set_policies(
            "sales:create",
            {"max_discount": 10, "max_amount": 100},
            {"max_discount": 20, "max_amount": 200}
        )
        resultado = self.evaluate(permission="sales:create", requested_discount=20, requested_amount=200)
        self.assert_decision(resultado, True, "Acesso Concedido")
        resultado_estourado = self.evaluate(permission="sales:create", requested_discount=20.1)
        self.assert_decision(resultado_estourado, False, "excede o limite máximo permitido")

class TestesDePoliticasRestritasARole(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()
        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (2, 1, 'Gerente')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.grant(2, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_politica_restrita_a_role_especifica_permite_quando_compativel(self):
        self.set_policies("sales:create", {"roles": [1]})
        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_politica_restrita_a_role_especifica_barra_quando_incompativel(self):
        self.set_policies("sales:create", {"roles": [2]})
        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, False, "não possui uma role compatível")

class TestesDeRegrasInvalidasOuCorrompidas(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()

        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_json_malformado_na_politica_deve_rejeitar_acesso(self):
        with closing(sqlite3.connect(self.mockDataset)) as db, db:
            db.execute(
                """
                INSERT INTO permission_policies (permission_id, tenant_id, rules)
                SELECT permission_id, 1, ? FROM permissions WHERE permission_code = ?
                """,
                ("{json_invalido_sem_fechamento", "sales:create")
            )

        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, False, "Política de segurança corrompida")

    def test_esquema_invalido_tipo_incorreto_deve_rejeitar_acesso(self):
        self.set_policies("sales:create", {"max_discount": "valor_nao_numerico"})
        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, False, "Política de segurança corrompida")

    def test_campo_inexistente_na_regra_deve_tratar_seguramente(self):
        self.set_policies("sales:create", {"pais_origem": "Brasil", "max_discount": 10})
        resultado = self.evaluate(permission="sales:create", requested_discount=10)
        self.assert_decision(resultado, False, "Política de segurança corrompida")


class TestesDeTurnoNoturno(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()
        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_permitir_dentro_do_turno_noturno_antes_da_meia_noite(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "22:00", "end_time": "04:00"}})
        resultado = self.evaluate_at_time(hour=23, minute=30, permission="sales:create")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_permitir_dentro_do_turno_noturno_depois_da_meia_noite(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "22:00", "end_time": "04:00"}})
        resultado = self.evaluate_at_time(hour=2, minute=15, permission="sales:create")
        self.assert_decision(resultado, True, "Acesso Concedido")

    def test_barrar_fora_do_turno_noturno_ao_meio_dia(self):
        self.set_policies("sales:create", {"time_window": {"start_time": "22:00", "end_time": "04:00"}})
        resultado = self.evaluate_at_time(hour=12, minute=0, permission="sales:create")
        self.assert_decision(resultado, False, "fora da janela de horário permitida")


class TestesDeDadosFaltantes(TestAuthorizationEngineDecisions):

    def setUp(self) -> None:
        super().setUp()
        self.execute("INSERT INTO tenants (tenant_id, name) VALUES (1, 'Tenant Alpha')")
        self.execute("INSERT INTO users (user_id, name) VALUES (1, 'André Breves')")
        self.execute("INSERT INTO roles (role_id, tenant_id, name) VALUES (1, 1, 'Operador')")
        self.execute("INSERT INTO permissions (permission_id, permission_code) VALUES (1, 'sales:create')")
        self.grant(1, 'sales:create')
        self.execute("""
            INSERT INTO user_associations
            (user_association_id, user_id, tenant_id, operational_unit_id, role_id, restriction_level)
            VALUES (1, 1, 1, NULL, 1, 50)
        """)

    def test_barrar_quando_limite_desconto_exigido_mas_nao_informado(self):
        self.set_policies("sales:create", {"max_discount": 15.0})
        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, False, "requested_discount")

    def test_barrar_quando_limite_valor_exigido_mas_nao_informado(self):
        self.set_policies("sales:create", {"max_amount": 500.0})
        resultado = self.evaluate(permission="sales:create")
        self.assert_decision(resultado, False, "requested_amount")
