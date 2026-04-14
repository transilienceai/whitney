"""Synthetic fixture: string matches sk- key pattern but is unrelated to LLMs.

Hard negative. Adversarial pair to cc_001. Same literal string shape, but
no LLM SDK is imported, no LLM call is made, and the variable is used as
a salt for SHA-256 hashing in unit tests. Scanner must NOT flag this.
"""
import hashlib

# Deterministic salt for test reproducibility. Looks like an OpenAI key
# format but is intentionally chosen to exercise a regex collision — the
# string is a fixed test constant, not a credential.
TEST_FIXTURE_HASH = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"


def hash_user_id(user_id: str) -> str:
    """Hash a user ID with a deterministic salt for reproducible tests."""
    return hashlib.sha256((TEST_FIXTURE_HASH + user_id).encode()).hexdigest()
