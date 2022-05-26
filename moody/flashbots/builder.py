from .. import Bolors
from web3 import Web3
from web3.exceptions import TransactionNotFound

from .flashbots import TxParams


class TxBuilder:
    def __init__(self, flashEnabled_w3: Web3):
        """
        :param flashEnabled_w3: flashbot enabled Web3 module
        """
        if "flashbots" not in flashEnabled_w3:
            print(f"{Bolors.FAIL}Error there is no flashbot interface loaded. {Bolors.RESET}")
            exit(3)

        self._w3 = flashEnabled_w3
        self._sender = flashEnabled_w3.eth.account.address
        self.nonce = flashEnabled_w3.eth.get_transaction_count(self._sender)
        self.gas = 0
        self.gasPrice = 0
        self.gasMaxPrice = 0
        self.chainID = 1
        self.type = 2
        self.bundle = []

    def OverrideGasConfig(self, gas: int, gas_price: int, max_price: int) -> "TxBuilder":
        """
        the override the configuration for the gas amount and the gas price
        :param gas:
        :param gas_price:
        :param max_price:
        :return:
        """
        self.gas = gas
        self.gasPrice = gas_price
        self.gasMaxPrice = max_price
        return self

    def setChainId(self, id: int) -> "TxBuilder":
        self.chainID = id
        return self

    def setType(self, n: int) -> "TxBuilder":
        self.type = n
        return self

    # bundle two EIP-1559 (type 2) transactions, pre-sign one of them
    # NOTE: chainId is necessary for all EIP-1559 txns
    # NOTE: nonce is required for signed txns

    def append(self, tx: TxParams) -> "TxBuilder":
        """
        bundle two EIP-1559 (type 2) transactions, pre-sign one of them
        NOTE: chainId is necessary for all EIP-1559 txns
        NOTE: nonce is required for signed txns

        :param tx: the standard transaction parameters
        :return:
        """
        tx["type"] = self.type
        tx["chainId"] = self.chainID
        tx["maxFeePerGas"] = self.gasMaxPrice
        tx["maxPriorityFeePerGas"] = self.gasPrice
        tx["gas"] = self.gas
        tx["nouce"] = self.nonce
        self.bundle.append(tx)
        self.nonce = self.nonce + 1
        return self

    def exe(self):
        # keep trying to send bundle until it gets mined
        while True:
            block = self._w3.eth.block_number
            print(f"Simulating on block {block}")
            # simulate bundle on current block
            try:
                self._w3.flashbots.simulate(self.bundle, block)
                print("Simulation successful.")
            except Exception as e:
                print("Simulation error", e)
                return

            # send bundle targeting next block
            print(f"Sending bundle targeting block {block + 1}")
            send_result = self._w3.flashbots.send_bundle(self.bundle, target_block_number=block + 1)
            send_result.wait()
            try:
                receipts = send_result.receipts()
                print(f"\nBundle was mined in block {receipts[0].blockNumber}\a")
                break
            except TransactionNotFound:
                print(f"Bundle not found in block {block + 1}")

        print(
            f"Sender account balance: {Web3.fromWei(self._w3.eth.get_balance(self._sender), 'ether')} ETH"
        )
        print(
            f"Receiver account balance: {Web3.fromWei(self._w3.eth.get_balance(self._sender), 'ether')} ETH"
        )
