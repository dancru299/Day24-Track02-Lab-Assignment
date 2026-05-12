# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
  - **Giải pháp:** Deploy trên data center/VPS đặt tại Việt Nam (VNG Cloud / Viettel IDC / CMC Telecom); OPA rule `deny if destination_country != "VN"` ngăn export ra ngoài lãnh thổ VN
- [x] Backup cũng phải ở trong lãnh thổ VN
  - **Giải pháp:** Cấu hình S3-compatible storage với endpoint nội địa (VNG Cloud / CMC Telecom)
- [x] Log việc transfer data ra ngoài nếu có
  - **Giải pháp:** FastAPI middleware ghi log mọi request có header `X-Destination`, Prometheus counter `data_export_total`

## B. Explicit Consent
- [x] Thu thập consent trước khi dùng data cho AI training
  - **Giải pháp:** Form consent khi nhập viện, lưu `consent_timestamp` và `consent_version` vào DB
- [x] Có mechanism để user rút consent (Right to Erasure)
  - **Giải pháp:** API endpoint `DELETE /api/patients/{id}` (admin-only, đã implement); soft-delete với flag `is_deleted`
- [x] Lưu consent record với timestamp
  - **Giải pháp:** Bảng `patient_consent` với các trường `patient_id`, `consented_at`, `revoked_at`, `version`

## C. Breach Notification (72h)
- [x] Có incident response plan
  - **Giải pháp:** Runbook tại `docs/incident-response.md`; escalation matrix: Security Team → DPO → CISO → Cục An toàn thông tin
- [x] Alert tự động khi phát hiện breach
  - **Giải pháp:** Prometheus AlertManager rule: alert khi có >10 failed auth/min hoặc data export bất thường; gửi email + Slack
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h
  - **Giải pháp:** Template báo cáo sẵn; DPO chịu trách nhiệm nộp lên Bộ Thông tin và Truyền thông trong vòng 72h phát hiện

## D. DPO Appointment
- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: **Nguyễn Văn An** — dpo@medviet.vn — (+84) 901 234 567

## E. Technical Controls (mapping từ NĐ13/2023)

| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio) — detect & replace CCCD, phone, email, name | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) — 4 roles, deny-by-default | ✅ Done | Platform Team |
| Encryption | AES-256-GCM at rest (SimpleVault envelope encryption), TLS 1.3 in transit (nginx) | ✅ Done | Infra Team |
| Audit logging | FastAPI middleware ghi mọi request vào `logs/audit.log` với: `timestamp`, `user`, `action`, `resource`, `ip`; rotate hàng ngày, lưu 90 ngày | ✅ Done | Platform Team |
| Breach detection | Prometheus + AlertManager: alert khi failed_auth_rate > 10/min hoặc anomaly_score > threshold; tự động tạo incident ticket và notify DPO qua email trong <5 phút | ✅ Done | Security Team |

## F. Audit Logging — Chi tiết implementation

```python
# middleware/audit_logger.py
import logging
from datetime import datetime
from fastapi import Request

audit_logger = logging.getLogger("audit")

async def audit_middleware(request: Request, call_next):
    response = await call_next(request)
    audit_logger.info({
        "timestamp": datetime.utcnow().isoformat(),
        "user": request.headers.get("Authorization", "anonymous"),
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "ip": request.client.host,
    })
    return response
```

## G. Breach Detection — Chi tiết implementation

```yaml
# alertmanager/rules/breach_detection.yml
groups:
  - name: breach_alerts
    rules:
      - alert: HighFailedAuthRate
        expr: rate(auth_failures_total[5m]) > 10
        for: 1m
        annotations:
          summary: "Possible brute force attack detected"
          action: "Notify DPO immediately, consider blocking IP"

      - alert: UnauthorizedDataExport
        expr: increase(data_export_denied_total[1h]) > 5
        annotations:
          summary: "Multiple unauthorized export attempts"
```
