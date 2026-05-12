# src/pii/anonymizer.py
import secrets
import string

import pandas as pd
from faker import Faker
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")

PII_COLUMNS = [
    "ho_ten",
    "cccd",
    "ngay_sinh",
    "so_dien_thoai",
    "email",
    "dia_chi",
    "bac_si_phu_trach",
]


def _fake_cccd() -> str:
    return "".join(secrets.choice(string.digits) for _ in range(12))


def _fake_phone() -> str:
    return "0" + secrets.choice("35789") + "".join(
        secrets.choice(string.digits) for _ in range(8)
    )


def _unique_replacements(count: int, forbidden: set[str], generator) -> list[str]:
    values = []
    seen = set(forbidden)
    for _ in range(count):
        value = str(generator())
        while value in seen:
            value = str(generator())
        values.append(value)
        seen.add(value)
    return values


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """Anonymize detected PII in free text."""
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace", {"new_value": _fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": _fake_phone()}),
            }
        elif strategy == "mask":
            operators = {
                "PERSON": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 8, "from_end": False},
                ),
                "EMAIL_ADDRESS": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 6, "from_end": False},
                ),
                "VN_CCCD": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 8, "from_end": False},
                ),
                "VN_PHONE": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 6, "from_end": True},
                ),
            }
        elif strategy == "hash":
            operators = {
                "PERSON": OperatorConfig("hash", {"hash_type": "sha256"}),
                "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_CCCD": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_PHONE": OperatorConfig("hash", {"hash_type": "sha256"}),
            }
        else:
            raise ValueError(f"Unsupported anonymization strategy: {strategy}")

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Anonymize patient data while preserving training features."""
        df_anon = df.copy()

        if "ho_ten" in df_anon.columns:
            df_anon["ho_ten"] = _unique_replacements(
                len(df_anon),
                set(df["ho_ten"].astype(str)),
                fake.name,
            )

        if "dia_chi" in df_anon.columns:
            df_anon["dia_chi"] = _unique_replacements(
                len(df_anon),
                set(df["dia_chi"].astype(str)),
                lambda: fake.address().replace("\n", ", "),
            )

        if "bac_si_phu_trach" in df_anon.columns:
            df_anon["bac_si_phu_trach"] = _unique_replacements(
                len(df_anon),
                set(df["bac_si_phu_trach"].astype(str)),
                fake.name,
            )

        if "email" in df_anon.columns:
            df_anon["email"] = [
                f"patient_{index:04d}@anon.medviet.local"
                for index in range(len(df_anon))
            ]

        if "cccd" in df_anon.columns:
            df_anon["cccd"] = _unique_replacements(
                len(df_anon),
                set(df["cccd"].astype(str).str.zfill(12)),
                _fake_cccd,
            )

        if "so_dien_thoai" in df_anon.columns:
            df_anon["so_dien_thoai"] = _unique_replacements(
                len(df_anon),
                set(df["so_dien_thoai"].astype(str).str.zfill(10)),
                _fake_phone,
            )

        if "ngay_sinh" in df_anon.columns:
            df_anon["ngay_sinh"] = df_anon["ngay_sinh"].astype(str).apply(
                lambda value: value.split("/")[-1] if "/" in value else value
            )

        return df_anon

    def calculate_detection_rate(
        self,
        original_df: pd.DataFrame,
        pii_columns: list,
    ) -> float:
        """Return the share of PII cells with at least one detected entity."""
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
