import pytest
from assertpy import assert_that
from blockchain.blockchain import Block
from dataclasses import replace


@pytest.fixture()
def root_block():
    root = Block.new_block('root')
    return root


@pytest.fixture()
def chain(root_block):
    chain = [root_block]
    for i in range(1, 3):
        chain.append(Block.new_block(i, chain[i-1]))
    return chain


class TestNewBlock:
    def test_create_root_block(self):
        root = Block.new_block('data')
        assert_that(root).is_not_none()
        assert_that(root).has_data('data')
        assert_that(root).has_previous_block(None)
        assert_that(root).has_previous_hash(b'')

    def test_create_child_block(self, root_block):
        block = Block.new_block('data', root_block)
        assert_that(block).is_not_none()
        assert_that(block).has_data('data')
        assert_that(block).has_previous_block(root_block)
        assert_that(block).has_previous_hash(root_block.compute_hash())


class TestVerify:
    @pytest.mark.skip
    def test_verify_root(self):
        root = Block.new_block('data')
        assert_that(root.verify()).is_equal_to(True)

    def test_verify_first_block(self, root_block):
        block = Block.new_block(1, root_block)
        assert_that(block).is_not_none()
        assert_that(block).has_data(1)
        assert_that(block).has_previous_block(root_block)
        assert_that(block).has_previous_hash(root_block.compute_hash())
        assert_that(block.verify()).is_equal_to(True)

    def test_verify_chain(self, chain):
        for block in chain[1:]:
            assert_that(block.verify()).is_equal_to(True)

    def test_change_data(self, chain):
        block = chain[-1]
        block = replace(block, data='asfd')
        assert_that(block.verify()).is_equal_to(True)

    def test_detect_data_tampering(self, chain):
        chain[1] = replace(chain[1], data='hacked')
        chain[2] = replace(chain[2], previous_block=chain[1])
        assert_that(chain[2].verify()).is_equal_to(False)

    def test_detect_block_insertion(self, chain):
        last_block = Block.new_block('last', chain[2])
        insert_block = Block.new_block('insert', chain[1])
        last_block = replace(last_block, previous_block=Block.new_block(chain[2].data, insert_block))
        assert_that(last_block.verify()).is_equal_to(False)
