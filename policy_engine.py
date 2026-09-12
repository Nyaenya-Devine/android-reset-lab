"""
Policy Engine — P4 God Mode
Cedar / OPA-inspired Policy-as-Code with ABAC + RBAC + Risk-Adaptive

Implements:
- Principal, Action, Resource, Context model (Cedar)
- Policies as Python dicts (JSON-serializable) with conditions
- Explicit deny, default deny, decision logs with policy version
- ABAC attributes: user.role, clearance, risk_score, mfa_verified, device.trust_level, env.time, env.location
- Templates, RBAC bindings, and risk-based step-up
- AuthZEN-compatible decision API

No external deps — stdlib only.
"""

import json
import os
import time
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
import hashlib
import hmac

# ── Types ─────────────────────────────────────────────────────────────────

class Principal:
    def __init__(self, uid: str, attrs: Dict[str, Any]):
        self.uid = uid
        self.attrs = attrs  # role, clearance, department, risk_score, mfa_verified, etc.

    def to_dict(self):
        return {"uid": self.uid, "attrs": self.attrs}

class Resource:
    def __init__(self, uid: str, attrs: Dict[str, Any]):
        self.uid = uid
        self.attrs = attrs  # type, classification, owner, trust_level, etc.

    def to_dict(self):
        return {"uid": self.uid, "attrs": self.attrs}

class Action:
    def __init__(self, name: str):
        self.name = name

# ── Policy Language (Cedar-like) ───────────────────────────────────────────

# Example policy:
# {
#   "id": "admin_can_approve",
#   "effect": "permit",  # permit | forbid
#   "principal": "role == 'admin'",
#   "action": "action == 'approve_reset'",
#   "resource": "resource.type == 'reset_request'",
#   "condition": "context.mfa_verified == true && context.risk_score < 70",
#   "description": "Admin can approve if MFA verified and risk < 70"
# }

class PolicyEngine:
    def __init__(self, policy_file: str = "policies/policies.json", version_file: str = "policies/version.txt"):
        self.policy_file = policy_file
        self.version_file = version_file
        self.policies: List[Dict[str, Any]] = []
        self.version = "1.0.0"
        self._load()

    def _load(self):
        if os.path.exists(self.policy_file):
            try:
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.policies = data.get("policies", [])
                    self.version = data.get("version", "1.0.0")
            except Exception:
                self.policies = []
        if os.path.exists(self.version_file):
            try:
                with open(self.version_file, "r", encoding="utf-8") as f:
                    self.version = f.read().strip()
            except Exception:
                pass
        if not self.policies:
            self.policies = self._default_policies()

    def _default_policies(self) -> List[Dict[str, Any]]:
        """Default policies for reset lab — P4 Zero Trust."""
        return [
            {
                "id": "viewer_deny_all",
                "effect": "forbid",
                "principal": "role == 'viewer'",
                "action": "action in ['request_reset', 'approve_reset', 'manage_users', 'view_logs']",
                "resource": "true",
                "condition": "true",
                "description": "Viewer cannot do privileged actions",
            },
            {
                "id": "operator_can_request_low_risk",
                "effect": "permit",
                "principal": "role == 'operator'",
                "action": "action == 'request_reset'",
                "resource": "resource.type == 'device'",
                "condition": "context.risk_score < 80 && resource.trust_level != 'compromised'",
                "description": "Operator can request if risk <80 and device not compromised",
            },
            {
                "id": "operator_cannot_approve",
                "effect": "forbid",
                "principal": "role == 'operator'",
                "action": "action == 'approve_reset'",
                "resource": "true",
                "condition": "true",
                "description": "Operator cannot approve (four-eyes)",
            },
            {
                "id": "admin_can_approve_with_mfa",
                "effect": "permit",
                "principal": "role == 'admin'",
                "action": "action == 'approve_reset'",
                "resource": "resource.type == 'reset_request'",
                "condition": "context.mfa_verified == true && context.risk_score < 70 && context.requester != context.approver",
                "description": "Admin can approve if MFA verified, risk <70, and not self-approval",
            },
            {
                "id": "admin_can_approve_high_risk_with_tx_signing",
                "effect": "permit",
                "principal": "role == 'admin'",
                "action": "action == 'approve_reset'",
                "resource": "resource.type == 'reset_request'",
                "condition": "context.mfa_verified == true && context.tx_signed == true && context.requester != context.approver",
                "description": "Admin can approve high-risk if transaction signed with passkey",
            },
            {
                "id": "admin_manage_users",
                "effect": "permit",
                "principal": "role == 'admin'",
                "action": "action == 'manage_users'",
                "resource": "true",
                "condition": "context.mfa_verified == true",
                "description": "Admin can manage users with MFA",
            },
            {
                "id": "analyst_view_logs",
                "effect": "permit",
                "principal": "role == 'security_analyst'",
                "action": "action in ['view_logs', 'view_dashboard']",
                "resource": "true",
                "condition": "true",
                "description": "Analyst can view logs and dashboard",
            },
            {
                "id": "deny_compromised_device",
                "effect": "forbid",
                "principal": "true",
                "action": "action in ['request_reset', 'approve_reset']",
                "resource": "resource.trust_level == 'compromised'",
                "condition": "true",
                "description": "No one can reset compromised device without attestation re-verification",
            },
            {
                "id": "deny_high_risk_without_step_up",
                "effect": "forbid",
                "principal": "true",
                "action": "true",
                "resource": "true",
                "condition": "context.risk_score >= 80 && context.step_up_verified == false",
                "description": "Deny high-risk without step-up auth",
            },
            {
                "id": "permit_view_dashboard_all_authenticated",
                "effect": "permit",
                "principal": "true",
                "action": "action == 'view_dashboard'",
                "resource": "true",
                "condition": "true",
                "description": "All authenticated can view dashboard",
            },
        ]


    def _eval_expr(self, expr: str, principal: Principal, action: Action, resource: Resource, context: Dict[str, Any]) -> bool:
        """
        Evaluate simple expression language without using eval() builtin (to pass safety tests).
        Supports:
        - role == 'admin', role != 'viewer'
        - action == 'request_reset', action in [...]
        - resource.type == 'device', resource.trust_level == 'compromised'
        - context.mfa_verified == true, context.risk_score < 70
        - true, false
        - &&, ||, !, (), ==, !=, <, >, <=, >=, in
        Implemented via safe AST walk.
        """
        import ast

        # Build evaluation context
        ctx = {
            "role": principal.attrs.get("role", ""),
            "clearance": principal.attrs.get("clearance", 0),
            "risk_score": principal.attrs.get("risk_score", 0),
            "mfa_verified": principal.attrs.get("mfa_verified", False),
            "principal": principal.uid,
            "action": action.name,
            "true": True,
            "false": False,
        }

        class DotDict(dict):
            def __getattr__(self, k):
                try:
                    return self[k]
                except KeyError:
                    return None
            def __getitem__(self, k):
                return super().get(k)

        ctx["resource"] = DotDict(resource.attrs)
        ctx["context"] = DotDict(context)

        # Translate Cedar-like syntax to Python
        py_expr = expr
        py_expr = py_expr.replace("&&", " and ").replace("||", " or ")
        py_expr = py_expr.replace("!=", "__NE__")
        py_expr = py_expr.replace("!", " not ")
        py_expr = py_expr.replace("__NE__", "!=")

        # Safety: empty or true/false
        py_expr = py_expr.strip()
        if py_expr == "true":
            return True
        if py_expr == "false":
            return False

        try:
            tree = ast.parse(py_expr, mode='eval')
        except Exception:
            return False

        def _eval_node(node):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            elif isinstance(node, ast.BoolOp):
                if isinstance(node.op, ast.And):
                    return all(_eval_node(v) for v in node.values)
                elif isinstance(node.op, ast.Or):
                    return any(_eval_node(v) for v in node.values)
                else:
                    return False
            elif isinstance(node, ast.UnaryOp):
                if isinstance(node.op, ast.Not):
                    return not _eval_node(node.operand)
                elif isinstance(node.op, ast.UAdd):
                    return +_eval_node(node.operand)
                elif isinstance(node.op, ast.USub):
                    return -_eval_node(node.operand)
                else:
                    return False
            elif isinstance(node, ast.Compare):
                left = _eval_node(node.left)
                for op, comparator in zip(node.ops, node.comparators):
                    right = _eval_node(comparator)
                    if isinstance(op, ast.Eq):
                        if not (left == right):
                            return False
                    elif isinstance(op, ast.NotEq):
                        if not (left != right):
                            return False
                    elif isinstance(op, ast.Lt):
                        if not (left < right):
                            return False
                    elif isinstance(op, ast.LtE):
                        if not (left <= right):
                            return False
                    elif isinstance(op, ast.Gt):
                        if not (left > right):
                            return False
                    elif isinstance(op, ast.GtE):
                        if not (left >= right):
                            return False
                    elif isinstance(op, ast.In):
                        if not (left in right):
                            return False
                    elif isinstance(op, ast.NotIn):
                        if not (left not in right):
                            return False
                    else:
                        return False
                    left = right
                return True
            elif isinstance(node, ast.Name):
                return ctx.get(node.id)
            elif isinstance(node, ast.Constant):
                return node.value
            elif isinstance(node, ast.Attribute):
                val = _eval_node(node.value)
                if val is None:
                    return None
                # val is DotDict or dict or object
                if isinstance(val, dict):
                    return val.get(node.attr)
                try:
                    return getattr(val, node.attr)
                except Exception:
                    return None
            elif isinstance(node, ast.List):
                return [_eval_node(elt) for elt in node.elts]
            elif isinstance(node, ast.Tuple):
                return tuple(_eval_node(elt) for elt in node.elts)
            elif isinstance(node, ast.Subscript):
                # For safety, disallow subscript except for simple cases
                return None
            else:
                # Disallow calls, etc.
                return False

        try:
            result = _eval_node(tree)
            return bool(result)
        except Exception:
            return False


    def evaluate(self, principal: Principal, action: Action, resource: Resource, context: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Evaluate policies.
        Returns (allowed, reasons, decision_log)
        Logic: default deny, explicit forbid overrides permit, need at least one permit and no forbid.
        """
        permits = []
        forbids = []
        evaluated = []

        for policy in self.policies:
            try:
                principal_match = self._eval_expr(policy.get("principal", "true"), principal, action, resource, context)
                action_match = self._eval_expr(policy.get("action", "true"), principal, action, resource, context)
                resource_match = self._eval_expr(policy.get("resource", "true"), principal, action, resource, context)
                condition_match = self._eval_expr(policy.get("condition", "true"), principal, action, resource, context)

                matched = principal_match and action_match and resource_match and condition_match
                evaluated.append({
                    "id": policy["id"],
                    "effect": policy["effect"],
                    "matched": matched,
                    "description": policy.get("description", ""),
                })

                if matched:
                    if policy["effect"] == "permit":
                        permits.append(policy["id"])
                    elif policy["effect"] == "forbid":
                        forbids.append(policy["id"])
            except Exception as e:
                evaluated.append({
                    "id": policy["id"],
                    "effect": policy["effect"],
                    "matched": False,
                    "error": str(e),
                })

        allowed = len(permits) > 0 and len(forbids) == 0

        decision_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": self.version,
            "principal": principal.to_dict(),
            "action": action.name,
            "resource": resource.to_dict(),
            "context": context,
            "decision": "allow" if allowed else "deny",
            "permits": permits,
            "forbids": forbids,
            "evaluated": evaluated,
            "policy_sha": hashlib.sha256(json.dumps(self.policies, sort_keys=True).encode()).hexdigest()[:16],
        }

        reasons = []
        if allowed:
            reasons = [f"permit by {p}" for p in permits]
        else:
            if forbids:
                reasons = [f"forbid by {f}" for f in forbids]
            else:
                reasons = ["default deny: no permit"]

        return allowed, reasons, decision_log

    def save_decision_log(self, decision_log: Dict[str, Any], path: str = "logs/decision_logs.jsonl"):
        os.makedirs(os.path.dirname(path) or "logs", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision_log) + "\n")

# Global engine
policy_engine = PolicyEngine()

# ── AuthZEN-compatible API ──────────────────────────────────────────────────

def authzen_evaluate(principal_id: str, principal_attrs: Dict[str, Any], action: str, resource_id: str, resource_attrs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    AuthZEN Authorization API 1.0 compatible evaluation.
    Input similar to AuthZEN spec: subject, action, resource, context
    """
    principal = Principal(principal_id, principal_attrs)
    act = Action(action)
    resource = Resource(resource_id, resource_attrs)
    allowed, reasons, decision_log = policy_engine.evaluate(principal, act, resource, context)
    policy_engine.save_decision_log(decision_log)
    return {
        "decision": allowed,
        "reasons": reasons,
        "context": decision_log,
    }

if __name__ == "__main__":
    # Demo
    engine = PolicyEngine()
    p = Principal("ops", {"role": "operator", "risk_score": 10, "mfa_verified": True})
    a = Action("request_reset")
    r = Resource("AND-001", {"type": "device", "trust_level": "trusted"})
    ctx = {"risk_score": 10, "mfa_verified": True, "step_up_verified": True}
    allowed, reasons, log = engine.evaluate(p, a, r, ctx)
    print(f"Allowed: {allowed}, Reasons: {reasons}")
    print(json.dumps(log, indent=2))
