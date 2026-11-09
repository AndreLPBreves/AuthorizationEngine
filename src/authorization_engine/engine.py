import json
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime

from pydantic import BaseModel, field_validator


class TimeWindow(BaseModel):
    start_time: str
    end_time: str

    @field_validator('start_time', 'end_time')
    @classmethod
    def validate_time_format(cls, v: str) -> str:
        pattern = r"^([01]\d|2[0-3]):([0-5]\d)$"
        if not re.match(pattern, v):
            raise ValueError(
                f"Horário inválido: '{v}'. O formato deve ser HH:MM (de 00:00 a 23:59)."
            )
        return v

class PolicyRuleSchema(BaseModel):
    model_config = {"extra": "forbid"}
    roles: list[int] | None = None
    max_discount: float | None = None
    max_amount: float | None = None
    time_window: TimeWindow | None = None
    ip_whitelist: list[str] | None = None
    ip_blacklist: list[str] | None = None

class UserPermissionPolicyRow(BaseModel):
    permission_code: str
    rules: PolicyRuleSchema | None = None

class AuthorizationEngine:

    @staticmethod
    def get_permission_policies(dataset_path: str, user_id: int, tenant_id: int, permission_code: str, operational_unit_id: int | None) -> list[sqlite3.Row]:
        sql = """
        SELECT
            p.permission_code,
            ua.user_id,
            ua.role_id,
            ua.operational_unit_id,
            ua.restriction_level,
            pp.rules
        FROM user_associations ua
        JOIN role_permissions rp
            ON ua.role_id = rp.role_id
        JOIN permissions p
            ON rp.permission_id = p.permission_id
        LEFT JOIN permission_policies pp
            ON p.permission_id = pp.permission_id
            AND pp.tenant_id = ua.tenant_id
        WHERE ua.user_id = :user_id
        AND ua.tenant_id = :tenant_id
        AND p.permission_code = :permission_code
        AND (
            (:operational_unit_id IS NULL AND ua.operational_unit_id IS NULL)
            OR
            (ua.operational_unit_id = :operational_unit_id)
        );
        """

        with closing(sqlite3.connect(dataset_path)) as db, db:
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            cursor.execute(sql, {
                "user_id": user_id,
                "tenant_id": tenant_id,
                "permission_code": permission_code,
                "operational_unit_id": operational_unit_id
            })
            rows = cursor.fetchall()

            return rows

    @staticmethod
    def get_target_association_details(
        dataset_path: str,
        tenant_id: int,
        target_user_association_id: int
    ) -> dict | None:
        """Retorna tanto o restriction_level quanto o user_id e role_id do alvo."""

        with closing(sqlite3.connect(dataset_path)) as db, db:
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            sql_target = """
            SELECT
                ua.user_id,
                ua.role_id,
                ua.restriction_level
            FROM user_associations ua
            WHERE ua.tenant_id = :tenant_id
            AND ua.user_association_id = :target_user_association_id
            """
            cursor.execute(sql_target, {
                "tenant_id": tenant_id,
                "target_user_association_id": target_user_association_id
            })
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "role_id": row["role_id"],
                "restriction_level": row["restriction_level"]
            }

    @staticmethod
    def evaluate(
        dataset_path: str,
        permission: str,
        user_id: int,
        tenant_id: int,
        ip: str,
        operational_unit_id: int | None = None,
        requested_discount: float | None = None,
        requested_amount: float | None = None,
        target_user_association_id: int | None = None,
        target_role_id: int | None = None,
        enable_benchmark: bool = False
    ) -> tuple[bool, str] | tuple[bool, str, dict]:

        tempos = {}
        t_global_inicio = time.perf_counter() if enable_benchmark else 0

        t0 = time.perf_counter() if enable_benchmark else 0
        raw_rows = AuthorizationEngine.get_permission_policies(
            dataset_path, user_id, tenant_id, permission, operational_unit_id
        )
        if enable_benchmark:
            tempos["db_lookup_ms"] = (time.perf_counter() - t0) * 1000

        if not AuthorizationEngine._usuario_tem_acesso(raw_rows):
            return (
                False,
                f"Acesso negado: O usuário {user_id} não possui a permissão '{permission}' atribuída no tenant {tenant_id}."
            )

        if not AuthorizationEngine._permissao_tem_politicas_configuradas(raw_rows):
            return (
                False,
                f"Acesso negado: O usuário {user_id} possui a permissão '{permission}', mas nenhuma política de segurança foi configurada para o tenant {tenant_id}."
            )

        if permission.startswith("user_association:") and target_user_association_id is not None:
            t0 = time.perf_counter() if enable_benchmark else 0
            erro_associacao = AuthorizationEngine._validar_mutacao_associacao(
                dataset_path, tenant_id, user_id, permission, target_user_association_id, raw_rows
            )
            if enable_benchmark:
                tempos["validate_association_mutation_ms"] = (time.perf_counter() - t0) * 1000
            if erro_associacao:
                return erro_associacao

        if permission.startswith("role:") and target_role_id is not None:
            t0 = time.perf_counter() if enable_benchmark else 0
            erro_role = AuthorizationEngine._validar_mutacao_role(
                user_id, permission, target_role_id, raw_rows
            )
            if enable_benchmark:
                tempos["validate_role_mutation_ms"] = (time.perf_counter() - t0) * 1000
            if erro_role:
                return erro_role

        t0 = time.perf_counter() if enable_benchmark else 0
        policies, erro_deserializacao = AuthorizationEngine._deserializar_politicas(raw_rows)
        if enable_benchmark:
            tempos["pydantic_deserialization_ms"] = (time.perf_counter() - t0) * 1000

        if erro_deserializacao:
            return erro_deserializacao

        t0 = time.perf_counter() if enable_benchmark else 0
        policies, erro_ip = AuthorizationEngine._filtrar_por_ip(policies, ip, user_id)
        if enable_benchmark:
            tempos["filter_ip_ms"] = (time.perf_counter() - t0) * 1000
        if erro_ip:
            return erro_ip

        t0 = time.perf_counter() if enable_benchmark else 0
        policies, erro_roles = AuthorizationEngine._filtrar_por_roles(policies, raw_rows, user_id, permission)
        if enable_benchmark:
            tempos["filter_roles_ms"] = (time.perf_counter() - t0) * 1000
        if erro_roles:
            return erro_roles

        t0 = time.perf_counter() if enable_benchmark else 0
        policies, erro_tempo = AuthorizationEngine._filtrar_por_tempo(policies, user_id)
        if enable_benchmark:
            tempos["filter_time_ms"] = (time.perf_counter() - t0) * 1000
        if erro_tempo:
            return erro_tempo

        t0 = time.perf_counter() if enable_benchmark else 0
        erro_limites = AuthorizationEngine._validar_limites(policies, requested_discount, requested_amount)
        if enable_benchmark:
            tempos["validate_limits_ms"] = (time.perf_counter() - t0) * 1000
        if erro_limites:
            return erro_limites

        if enable_benchmark:
            tempos["total_evaluate_ms"] = (time.perf_counter() - t_global_inicio) * 1000
            return (True, "Acesso Concedido", tempos)

        return (True, "Acesso Concedido")

    @staticmethod
    def _usuario_tem_acesso(rows: list[sqlite3.Row]) -> bool:
        return bool(rows)

    @staticmethod
    def _permissao_tem_politicas_configuradas(rows: list[sqlite3.Row]) -> bool:
        return any(row["rules"] is not None for row in rows)

    @staticmethod
    def _validar_mutacao_associacao(dataset_path, tenant_id, user_id, permission, target_user_association_id, raw_rows):
        target_details = AuthorizationEngine.get_target_association_details(
            dataset_path, tenant_id, target_user_association_id
        )

        if not target_details:
            return (False, f"Associação alvo ID {target_user_association_id} não encontrada no tenant {tenant_id}.")

        if target_details["user_id"] == user_id:
            return (False, "Acesso negado: Usuários não podem modificar suas próprias associações de segurança.")

        global_admin_rows = [r for r in raw_rows if r["operational_unit_id"] is None and r["permission_code"].startswith("user_association:")]

        if not global_admin_rows:
            return (False, f"Acesso negado: O usuário {user_id} não possui um cargo administrativo global com a permissão '{permission}'.")

        actor_best_level = min(r["restriction_level"] for r in global_admin_rows)
        target_level = target_details["restriction_level"]

        if actor_best_level <= target_level:
            return (
                False,
                f"Acesso negado por hierarquia: Seu nível restritivo global ({actor_best_level}) é insuficiente para alterar o alvo (nível {target_level})."
            )
        return None

    @staticmethod
    def _validar_mutacao_role(user_id, permission, target_role_id, raw_rows):
        actor_roles = {r["role_id"] for r in raw_rows}
        if target_role_id in actor_roles:
            return (False, "Acesso negado: Usuários não podem modificar permissões ou propriedades da role que eles próprios possuem.")

        global_admin_rows = [r for r in raw_rows if r["operational_unit_id"] is None and r["permission_code"].startswith("role:")]

        if not global_admin_rows:
            return (False, f"Acesso negado: O usuário {user_id} não possui um cargo administrativo global para gerenciar roles.")
        return None

    @staticmethod
    def _deserializar_politicas(raw_rows) -> tuple[list[UserPermissionPolicyRow] | None, tuple[bool, str] | None]:
        policies = []
        for row in raw_rows:
            raw_rules = row["rules"]
            parsed_rules = None

            if raw_rules:
                try:
                    rule_dict = json.loads(raw_rules)
                    parsed_rules = PolicyRuleSchema(**rule_dict)
                except (json.JSONDecodeError, ValueError) as e:
                    return None, (
                        False,
                        f"Acesso negado: Política de segurança corrompida ou com formato inválido para a permissão '{row['permission_code']}'.\n{e}"
                    )

            policies.append(
                UserPermissionPolicyRow(
                    permission_code=row["permission_code"],
                    rules=parsed_rules
                )
            )
        return policies, None

    @staticmethod
    def _filtrar_por_ip(policies, ip, user_id):
        has_any_whitelist = any(p.rules and p.rules.ip_whitelist for p in policies)

        if has_any_whitelist:
            if not ip:
                return None, (False, f"Acesso negado para o usuário {user_id}: IP de origem obrigatório não fornecido.")
            policies = [
                p for p in policies
                if p.rules and p.rules.ip_whitelist and ip in p.rules.ip_whitelist
            ]
        else:
            if not ip:
                return None, (False, f"Acesso negado para o usuário {user_id}: IP de origem obrigatório não fornecido.")
            policies = [
                p for p in policies
                if not (p.rules and p.rules.ip_blacklist and ip in p.rules.ip_blacklist)
            ]

        if not policies:
            return None, (False, f"Acesso negado para o usuário {user_id}: bloqueado pelas regras de IP.")

        return policies, None

    @staticmethod
    def _filtrar_por_roles(policies, raw_rows, user_id, permission):
        user_roles = {r["role_id"] for r in raw_rows}
        filtered_policies = [
            p for p in policies
            if p.rules.roles is None
            or any(r in user_roles for r in p.rules.roles)
        ]

        if not filtered_policies:
            return None, (
                False,
                f"Acesso negado: O usuário {user_id} não possui uma role compatível com as políticas de segurança da permissão '{permission}'."
            )
        return filtered_policies, None

    @staticmethod
    def _filtrar_por_tempo(policies, user_id):
        current_time_str = datetime.now().strftime("%H:%M")
        valid_policies = []

        for p in policies:
            if not p.rules or not p.rules.time_window:
                valid_policies.append(p)
                continue

            tw = p.rules.time_window
            start = tw.start_time
            end = tw.end_time

            if start <= end:
                dentro = start <= current_time_str <= end
            else:
                dentro = current_time_str >= start or current_time_str <= end

            if dentro:
                valid_policies.append(p)

        if not valid_policies:
            return None, (False, f"Acesso negado para o usuário {user_id}: fora da janela de horário permitida.")

        return valid_policies, None

    @staticmethod
    def _validar_limites(policies, requested_discount, requested_amount):
        valid_discounts: list[float] = []
        valid_amounts: list[float] = []
        has_unlimited_discount = False
        has_unlimited_amount = False

        for p in policies:
            rules = p.rules

            if rules.max_discount is None:
                has_unlimited_discount = True
            else:
                valid_discounts.append(rules.max_discount)

            if rules.max_amount is None:
                has_unlimited_amount = True
            else:
                valid_amounts.append(rules.max_amount)

        if valid_discounts and not has_unlimited_discount and requested_discount is None:
            return (False, "Acesso negado: O parâmetro 'requested_discount' é obrigatório para avaliar esta operação.")

        if requested_discount is not None and not has_unlimited_discount:
            max_allowed_discount = max(valid_discounts) if valid_discounts else 0.0
            if requested_discount > max_allowed_discount:
                return (False, f"Desconto de {requested_discount}% excede o limite máximo permitido de {max_allowed_discount}%.")

        if valid_amounts and not has_unlimited_amount and requested_amount is None:
            return (False, "Acesso negado: O parâmetro 'requested_amount' é obrigatório para avaliar esta operação.")

        if requested_amount is not None and not has_unlimited_amount:
            max_allowed_amount = max(valid_amounts) if valid_amounts else 0.0
            if requested_amount > max_allowed_amount:
                return (False, f"Valor de {requested_amount} excede o limite máximo permitido de {max_allowed_amount}.")

        return None
