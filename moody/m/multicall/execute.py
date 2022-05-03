from web3.contract import Contract
from typing import Tuple, List, Union
from ..bases import ContractBase
from ..multicall import Multicall
from ...libeb import MiliDoS
from eth_utils import to_checksum_address


class MultiCallerV1Contract:
    """
    Need some tests, help is needed
    """
    def __init__(self, moon: MiliDoS, address: str):
        self._moon = moon
        self._address = address
        self._data = []
        self._callersetup()

    def _callersetup(self):
        self.caller: Multicall = Multicall(self._moon, self._address).CallAutoConf(self._moon).CallDebug(True)

    def Config(self) -> Multicall:
        """
        You may want to do more with the original instance
        :return: instance of the call
        """
        return self.caller

    def getInfo(self, address: str, abi: str) -> Contract:
        return self._moon.w3.eth.contract(address=address, abi=abi)

    def addCallClassic(self, contract: str, abi: str, method: str, params: list) -> "MultiCallerV1Contract":
        hex = self.getInfo(contract, abi).encodeABI(fn_name=method, args=params)
        self._data.append(hex)
        return self

    def addCallEasy(self, contract: ContractBase, method: str, params: list) -> "MultiCallerV1Contract":
        hex = self.getInfo(
            to_checksum_address(contract.contract_address),
            contract.fromAbi
        ).encodeABI(fn_name=method, args=params)
        self._data.append(hex)
        return self

    def execute(self) -> None:
        self.caller.aggregate(self._data)

    def executeSimple(self) -> Tuple[int, List[Union[bytes, str]]]:
        """
        gives the returns of the block number
        :return:  (blocknumber, hash, results)
        """
        (blocknum, data) = self.caller.aggregate(self._data)
        return (blocknum, data)
