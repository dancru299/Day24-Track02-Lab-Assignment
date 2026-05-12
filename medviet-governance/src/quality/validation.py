# src/quality/validation.py
import pandas as pd
import great_expectations as gx
from great_expectations.expectations import (
    ExpectColumnValueLengthsToEqual,
    ExpectColumnValuesToBeBetween,
    ExpectColumnValuesToBeInSet,
    ExpectColumnValuesToMatchRegex,
    ExpectColumnValuesToNotBeNull,
    ExpectColumnValuesToBeUnique,
)

VALID_DISEASES = {"Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"}
PII_COLUMNS = [
    "ho_ten",
    "cccd",
    "ngay_sinh",
    "so_dien_thoai",
    "email",
    "dia_chi",
    "bac_si_phu_trach",
]
NON_PII_COLUMNS = ["patient_id", "benh", "ket_qua_xet_nghiem", "ngay_kham"]

STRING_DTYPES = {
    "patient_id": str,
    "ho_ten": str,
    "cccd": str,
    "ngay_sinh": str,
    "so_dien_thoai": str,
    "email": str,
    "dia_chi": str,
    "benh": str,
    "bac_si_phu_trach": str,
    "ngay_kham": str,
}


def _read_for_expectations(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, dtype=STRING_DTYPES)
    df["ket_qua_xet_nghiem"] = pd.to_numeric(
        df["ket_qua_xet_nghiem"],
        errors="coerce",
    )
    return df


def build_patient_expectation_suite():
    """Create and validate the Great Expectations suite for patient data."""
    context = gx.get_context(mode="ephemeral")

    df = _read_for_expectations("data/raw/patients_raw.csv")
    ds = context.data_sources.add_pandas("patient_ds")
    asset = ds.add_dataframe_asset("patient_df")
    batch_def = asset.add_batch_definition_whole_dataframe("full_batch")

    suite = context.suites.add(gx.ExpectationSuite(name="patient_data_suite"))

    suite.add_expectation(ExpectColumnValuesToNotBeNull(column="patient_id"))
    suite.add_expectation(ExpectColumnValueLengthsToEqual(column="cccd", value=12))
    suite.add_expectation(ExpectColumnValuesToBeBetween(
        column="ket_qua_xet_nghiem",
        min_value=0,
        max_value=50,
    ))
    suite.add_expectation(ExpectColumnValuesToBeInSet(
        column="benh",
        value_set=list(VALID_DISEASES),
    ))
    suite.add_expectation(ExpectColumnValuesToMatchRegex(
        column="email",
        regex=r"[^@]+@[^@]+\.[^@]+",
    ))
    suite.add_expectation(ExpectColumnValuesToBeUnique(column="patient_id"))

    validation_definition = context.validation_definitions.add(
        gx.ValidationDefinition(name="patient_vd", data=batch_def, suite=suite)
    )
    result = validation_definition.run(batch_parameters={"dataframe": df})
    print(f"Expectation suite built: {result.success}")

    return suite


def validate_anonymized_data(filepath: str) -> dict:
    """Validate anonymized data with focused pandas checks."""
    df = pd.read_csv(filepath, dtype=str)
    failed = []

    try:
        df_raw = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    except FileNotFoundError:
        df_raw = None

    missing_columns = [
        col for col in PII_COLUMNS + NON_PII_COLUMNS if col not in df.columns
    ]
    if missing_columns:
        failed.append(f"Missing columns: {missing_columns}")

    if df_raw is not None:
        for col in PII_COLUMNS:
            if col in df.columns and col in df_raw.columns:
                leaked = set(df_raw[col].astype(str)) & set(df[col].astype(str))
                if leaked:
                    failed.append(
                        f"PII leak in {col}: {len(leaked)} original values remain"
                    )

        if len(df) != len(df_raw):
            failed.append(f"Row count mismatch: {len(df)} vs {len(df_raw)}")

        for col in NON_PII_COLUMNS:
            if col in df.columns and col in df_raw.columns:
                if not df[col].reset_index(drop=True).equals(
                    df_raw[col].reset_index(drop=True)
                ):
                    failed.append(f"{col} column was altered")

    critical_cols = ["patient_id", "benh", "ket_qua_xet_nghiem"]
    for col in critical_cols:
        if col in df.columns and df[col].isnull().any():
            failed.append(f"Null values found in column: {col}")

    if "cccd" in df.columns and not df["cccd"].str.match(r"^\d{12}$").all():
        failed.append("Anonymized cccd values must be 12 digits")

    if (
        "so_dien_thoai" in df.columns
        and not df["so_dien_thoai"].str.match(r"^0[35789]\d{8}$").all()
    ):
        failed.append("Anonymized phone values must match VN phone format")

    return {
        "success": len(failed) == 0,
        "failed_checks": failed,
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns),
        },
    }
