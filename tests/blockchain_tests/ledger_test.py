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
    def test_create_root_block(self):
        block = TransactionBlock.new_block()
        assert_that(block).is_type_of(TransactionBlock)
        assert_that(block).is_not_none()
        assert_that(block).has_data(())
        assert_that(block.previous_block).is_none()
        assert_that(block.previous_hash).is_equal_to(b'')
        assert_that(block.nonce).is_none()

    def test_create_child_block(self, root_block):
        block = TransactionBlock.new_block(previous_block=root_block)
        assert_that(block).is_type_of(TransactionBlock)
        assert_that(block).is_not_none()
        assert_that(block).has_data(())
        assert_that(block.previous_block).is_equal_to(root_block)
        assert_that(block.previous_hash).is_equal_to(root_block.compute_hash())
        assert_that(block.nonce).is_none()

    def test_create_block_with_data(self, root_block):
        block = TransactionBlock.new_block(('transaction', ), root_block)
        assert_that(block).is_not_none()
        assert_that(block).has_data(('transaction', ))
        assert_that(block.previous_block).is_equal_to(root_block)
        assert_that(block.previous_hash).is_equal_to(root_block.compute_hash())
        assert_that(block.nonce).is_none()


class TestAddTransaction:
    def test_add_first_transaction(self, root_block):
        block = TransactionBlock.new_block(previous_block=root_block)
        block = block.add_transaction('transaction')
        assert_that(block).has_data(('transaction', ))

    def test_add_to_existing_transactions(self, root_block):
        block = TransactionBlock.new_block(('trx1', ), root_block)
        block = block.add_transaction('trx2')
        assert_that(block).has_data(('trx1', 'trx2'))


class TestAddTransactions:
    def test_add_first_transactions(self, root_block):
        block = TransactionBlock.new_block(previous_block=root_block)
        block = block.add_transactions(('trx1', 'trx2'))
        assert_that(block).has_data(('trx1', 'trx2'))

    def test_add_to_existing_transactions(self, root_block):
        block = TransactionBlock.new_block(('trx1', 'trx2'), root_block)
        block = block.add_transactions(('trx3', 'trx4'))
        assert_that(block).has_data(('trx1', 'trx2', 'trx3', 'trx4'))

    def test_add_with_single_element_tuple(self, root_block):
        block = TransactionBlock.new_block(('trx1', 'trx2'), root_block)
        block = block.add_transactions(('trx3',))
        assert_that(block).has_data(('trx1', 'trx2', 'trx3'))
