from typing import Tuple, List, Union

from ..bases import ContractBase
from ..multicall2 import Multicall2
from ..multicall.execute import MultiCallerV1Contract
from ...libeb import MiliDoS


class MultiCallerContract(MultiCallerV1Contract):
    def __init__(self, moon: MiliDoS, address: str):
        super().__init__(moon, address)

    def _callersetup(self):
        self.caller: Multicall2 = Multicall2(self._moon, self._address).CallAutoConf(self._moon).CallDebug(True)

    def Config(self) -> Multicall2:
        return self.caller

    def addCallClassic(self, contract: str, abi: str, method: str, params: list) -> "MultiCallerContract":
        super().addCallClassic(contract, abi, method, params)
        return self

    def addCallEasy(self, contract: ContractBase, method: str, params: list) -> "MultiCallerContract":
        super().addCallEasy(contract, method, params)
        return self

    def executeSimple(self) -> Tuple[int, List[Union[bytes, str]]]:
        """
        gives the returns of the block number
        :return:  (blocknumber, hash, results)
        """
        (blocknum, data) = self.caller.aggregate(self._data)
        return (blocknum, data)

    def executeTry(self) -> List[Union[bytes, str]]:
        return self.caller.try_aggregate(True, self._data)

    def executeTryWithBlock(self) -> Tuple[int, Union[bytes, str], List[Union[bytes, str]]]:
        """
        gives the block dat and the results
        :return:  (blocknumber, hash, results)
        """
        return self.caller.try_block_and_aggregate(True, self._data)
