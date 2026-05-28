"""IAMScope auth module."""

from iamscope.auth.assume_role import assume_collection_role, get_caller_identity
from iamscope.auth.session import get_client, get_session

__all__ = [
    "assume_collection_role",
    "get_caller_identity",
    "get_client",
    "get_session",
]
