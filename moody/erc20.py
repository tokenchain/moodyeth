import random
from datetime import datetime

from web3 import Web3

from .libeb import MiliDoS
from .m.pharaohs import pharaohs


class ERC20H(MiliDoS):
    def __init__(self, network):
        super().__init__(network)
        self.TokenContract: pharaohs = None
        self.MasterContract: pharaohs = None

    def generateHash(self) -> bytes:
        gTime = int(datetime.now().timestamp())
        rKey = random.randint(15000000, gTime)
        eHash = Web3.solidityKeccak(["uint256"], [rKey])
        return eHash

    @property
    def TokenAddress(self) -> str:
        if "TokenTrc20" in self._contract_dict:
            return self.getAddr("TokenTrc20")
        else:
            raise ValueError("not BSend contract address is found")

    @property
    def ERC20Address(self) -> str:
        if "ERC20" in self._contract_dict:
            return self.getAddr("ERC20")
        else:
            raise ValueError("not ERC20 contract address is found")

    def deploy_Coin(self):
        if self.is_deployment():
            print("=== Deploy contract with this settings {}".format("TokenTrc20"))
            self.deploy("TokenTrc20", [], 10 ** 9, 1)

    def deploy_Multi(self):
        if self.is_deployment():
            print("=== Deploy contract with this settings {}".format("TokenTrc20"))
            self.deploy("BSend", [], 10 ** 9, 1)

    def SetupContract(self):
        self.TokenContract = pharaohs(self, self.TokenAddress).CallDebug(False).CallContractFee(10000000)
        self.MasterContract = pharaohs(self, self.ERC20Address).CallDebug(False).CallContractFee(10000000)
