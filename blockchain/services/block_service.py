from nameko.rpc import rpc


class BlockService:
    name = 'block_service'

    @rpc
    def verify_block(self, block_address, block_hash):
        pass

    @rpc
    def get_block(self, block_address):
        pass
