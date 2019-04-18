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
    # chain = [root_block]
    # for i in range(1, 10):
    #     chain.append(Block.new_block(i, chain[i-1]))
    block = root_block
    for i in range(10):
        block = Block.new_block(i, block)
    return block


def test_root_block():
    root = Block.new_block('data')
    assert_that(root).is_not_none()
    assert_that(root).has_data('data')
    assert_that(root).has_previous_block(None)
    assert_that(root).has_previous_hash(b'')


@pytest.mark.skip
def test_verify_root():
    root = Block.new_block('data')
    assert_that(root.verify()).is_equal_to(True)


def test_verify_first_block(root_block):
    block = Block.new_block(1, root_block)
    assert_that(block).is_not_none()
    assert_that(block).has_data(1)
    assert_that(block).has_previous_block(root_block)
    assert_that(block).has_previous_hash(root_block.compute_hash())
    assert_that(block.verify()).is_equal_to(True)


def test_verify_chain(chain):
    for block in chain:
        assert_that(block.verify()).is_equal_to(True)


def test_catch_tampering(chain):
    bad_block = chain[4]
    bad_block = replace(bad_block, data='hacked')
    assert_that(bad_block.verify()).is_equal_to(True)
