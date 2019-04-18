from nameko.rpc import rpc


class BlockService:
    name = 'block_service'

    @rpc
    def new_transaction_block(self, transactions):
        pass
