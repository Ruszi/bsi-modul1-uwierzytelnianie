"""Pomocnicze funkcje czasu.
Wszystkie daty w bazie zapisujemy w UTC jako tekst ISO 8601,
np. '2026-10-13T09:30:00+00:00', żeby nie mieszać stref czasowych."""
from datetime import datetime, timezone


def now():
    """Aktualny czas w UTC (bez ułamków sekund)."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(dt):
    """datetime -> tekst do zapisania w bazie (None zostaje None)."""
    return dt.isoformat() if dt else None


def from_iso(value):
    """Tekst z bazy -> datetime (None zostaje None)."""
    return datetime.fromisoformat(value) if value else None