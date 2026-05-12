# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

def build_vietnamese_analyzer() -> AnalyzerEngine:
    # --- TASK 2.2.1 ---
    # CCCD VN: đúng 12 chữ số, có word boundary tránh match số dài hơn
    cccd_pattern = Pattern(
        name="cccd_pattern",
        regex=r"\b\d{12}\b",
        score=0.9
    )
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        patterns=[cccd_pattern],
        context=["cccd", "căn cước", "chứng minh", "cmnd"],
        supported_language="vi"
    )

    # --- TASK 2.2.2 ---
    # Số điện thoại VN: 0 + [3|5|7|8|9] + 8 chữ số
    phone_recognizer = PatternRecognizer(
        supported_entity="VN_PHONE",
        patterns=[Pattern(
            name="vn_phone",
            regex=r"\b0[35789]\d{8}\b",
            score=0.85
        )],
        context=["điện thoại", "sdt", "phone", "liên hệ"],
        supported_language="vi"
    )

    # The available multilingual spaCy model misses many Vietnamese/Faker names.
    # This recognizer catches 2-5 capitalized tokens such as "Nguyen Van A".
    name_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        patterns=[Pattern(
            name="vn_person_name",
            regex=r"\b[A-Z][^\s,.;:()/-]*(?:\s+[A-Z][^\s,.;:()/-]*){1,4}\b",
            score=0.75
        )],
        context=["benh nhan", "ho ten", "bac si", "patient", "doctor"],
        supported_language="vi"
    )

    # --- TASK 2.2.3 ---
    # Dùng xx_ent_wiki_sm (multilingual) vì vi_core_news_lg không tương thích spaCy 3.8
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "vi",
                    "model_name": "xx_ent_wiki_sm"}]
    })
    nlp_engine = provider.create_engine()

    # --- TASK 2.2.4 ---
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["vi"])
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(name_recognizer)

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect PII trong text tiếng Việt."""
    results = analyzer.analyze(
        text=text,
        language="vi",
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
    )
    return results
