import time
from . import server_utils, config


def test_validate_internal_nonce_pruning():
    server_utils.reset_caches()
    old_nonce = "old"
    # Insert an expired nonce manually
    server_utils.used_internal_nonces[old_nonce] = time.time() - (config.INTERNAL_NONCE_EXPIRY_SECONDS + 1)
    new_nonce = "new"
    assert server_utils.validate_internal_nonce(new_nonce)
    # Old nonce should be pruned
    assert old_nonce not in server_utils.used_internal_nonces
    # Reusing new nonce before expiry should fail
    assert not server_utils.validate_internal_nonce(new_nonce)
