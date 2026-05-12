# tests/test_pii.py
import pandas as pd
import pytest

from src.pii.anonymizer import MedVietAnonymizer


@pytest.fixture(scope="module")
def anonymizer():
    return MedVietAnonymizer()


@pytest.fixture(scope="module")
def sample_df():
    return pd.read_csv("data/raw/patients_raw.csv", dtype=str).head(50)


class TestPIIDetection:

    def test_name_detected(self, anonymizer):
        cccd = "012345" + "678901"
        text = f"Benh nhan Nguyen Van A, CCCD: {cccd}"
        results = anonymizer.analyzer.analyze(
            text=text,
            language="vi",
            entities=["PERSON"],
        )
        assert len(results) > 0, "Person name was not detected"

    def test_cccd_detected(self, anonymizer):
        cccd = "012345" + "678901"
        text = f"Benh nhan Nguyen Van A, CCCD: {cccd}"
        results = anonymizer.analyzer.analyze(
            text=text,
            language="vi",
            entities=["VN_CCCD"],
        )
        assert len(results) > 0, "CCCD was not detected"

    def test_phone_detected(self, anonymizer):
        text = "Lien he: 0912345678"
        results = anonymizer.analyzer.analyze(
            text=text,
            language="vi",
            entities=["VN_PHONE"],
        )
        assert len(results) > 0, "Phone number was not detected"

    def test_email_detected(self, anonymizer):
        text = "Email: nguyenvana@gmail.com"
        results = anonymizer.analyzer.analyze(
            text=text,
            language="vi",
            entities=["EMAIL_ADDRESS"],
        )
        assert len(results) > 0, "Email was not detected"

    def test_detection_rate_above_95_percent(self, anonymizer, sample_df):
        pii_columns = ["ho_ten", "cccd", "so_dien_thoai", "email"]
        rate = anonymizer.calculate_detection_rate(sample_df, pii_columns)
        print(f"\nDetection rate: {rate:.2%}")
        assert rate >= 0.95, f"Detection rate {rate:.2%} < 95%"


class TestAnonymization:

    def test_original_pii_values_not_in_output(self, anonymizer, sample_df):
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        pii_columns = [
            "ho_ten",
            "cccd",
            "ngay_sinh",
            "so_dien_thoai",
            "email",
            "dia_chi",
            "bac_si_phu_trach",
        ]
        for col in pii_columns:
            leaked = set(sample_df[col].astype(str)) & set(df_anon[col].astype(str))
            assert not leaked, f"Original PII values remain in {col}: {leaked}"

    def test_non_pii_columns_unchanged(self, anonymizer, sample_df):
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        for col in ["patient_id", "benh", "ket_qua_xet_nghiem", "ngay_kham"]:
            pd.testing.assert_series_equal(
                sample_df[col].reset_index(drop=True),
                df_anon[col].reset_index(drop=True),
                check_names=False,
            )
