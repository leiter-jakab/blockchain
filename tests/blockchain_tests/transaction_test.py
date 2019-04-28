import pytest
from assertpy import assert_that
from blockchain.cryptocurrency.transaction import Transaction
from blockchain.signing import generate_keys, serialize_public_key


@pytest.fixture()
def keys():
    keys = [generate_keys() for _ in range(5)]
    return zip(*keys)


def test_new_transaction(keys):
    _, pubs = keys
    tr = (Transaction()
          .add_input(pubs[0], 1)
          .add_output(pubs[1], 1))
    assert_that(tr).is_not_none()
    assert_that(tr).has_inputs(((serialize_public_key(pubs[0]), 1, b''),))
    assert_that(tr).has_outputs(((serialize_public_key(pubs[1]), 1),))
