from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def normalize_report_key(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def reject_forbidden_report_keys(
    value: Any,
    *,
    forbidden_key_terms: Iterable[str],
    allowed_safe_keys: Iterable[str],
    report_label: str,
    path: str = "$",
) -> None:
    normalized_forbidden_terms = tuple(normalize_report_key(term) for term in forbidden_key_terms)
    safe_keys = set(allowed_safe_keys)
    _reject_forbidden_report_keys(
        value,
        forbidden_key_terms=normalized_forbidden_terms,
        allowed_safe_keys=safe_keys,
        report_label=report_label,
        path=path,
    )


def _reject_forbidden_report_keys(
    value: Any,
    *,
    forbidden_key_terms: tuple[str, ...],
    allowed_safe_keys: set[str],
    report_label: str,
    path: str,
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized_key = normalize_report_key(key_text)
            if key_text not in allowed_safe_keys and _has_forbidden_key_term(
                normalized_key,
                forbidden_key_terms=forbidden_key_terms,
            ):
                raise ValueError(f"forbidden {report_label} field at {path}.{key}: {key}")
            _reject_forbidden_report_keys(
                child,
                forbidden_key_terms=forbidden_key_terms,
                allowed_safe_keys=allowed_safe_keys,
                report_label=report_label,
                path=f"{path}.{key}",
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_report_keys(
                child,
                forbidden_key_terms=forbidden_key_terms,
                allowed_safe_keys=allowed_safe_keys,
                report_label=report_label,
                path=f"{path}[{index}]",
            )


def _has_forbidden_key_term(normalized_key: str, *, forbidden_key_terms: tuple[str, ...]) -> bool:
    return any(term in normalized_key for term in forbidden_key_terms)
