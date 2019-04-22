import pytest
from assertpy import assert_that
from blockchain.cryptocurrency.ledger import TransactionBlock
from blockchain.cryptocurrency.transaction import VERIFIED, SIGNING_ERROR


@pytest.fixture()
def good_transaction(mocker):
    tr = mocker.Mock()
    tr.verify.return_value = tr, VERIFIED, 'message'
    return tr


@pytest.fixture()
def bad_transaction(mocker):
    tr = mocker.Mock()
    tr.verify.return_value = tr, SIGNING_ERROR, 'message'


@pytest.fixture()
def root_block(good_transaction):
    root_block = TransactionBlock.new_block(data=(good_transaction,), previous_block=None)
    return root_block


class TestNewBlock:
    def test_new_block(self):
        block = TransactionBlock.new_block()
        assert_that(block).is_type_of(TransactionBlock)
        assert_that(block).is_not_none()
        assert_that(block).has_data(())
        assert_that(block.previous_block).is_none()
        assert_that(block.previous_hash).is_equal_to(b'')
        assert_that(block.nonce).is_none()


class TestAddTransaction:
    def test_add_transactions(self, root_block, good_transaction):
        block = TransactionBlock.new_block(previous_block=root_block)
        block = block.add_transaction(good_transaction)
        assert_that(block.data).is_type_of(tuple)
        assert_that(block.previous_hash).is_equal_to(block.previous_block.compute_hash())
        assert_that(block.verify()).contains(VERIFIED)
