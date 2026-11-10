from __future__ import annotations

from .models import Checkpoint


AUTHENTICATION_CHECKPOINT = Checkpoint("CN-28", 28, "身份认证机制评估模块", "CN-IAM-001", "动态访问控制与身份安全评估", 1.1, ["认证覆盖", "匿名访问", "ServiceAccount token"], ["RBAC", "ServiceAccount", "Pod", "PeerAuthentication", "APIServer"])
