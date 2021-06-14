from moody.libeb import MiliDoS
from moody.m.erc20 import ERC20
from . import Token

# from codec.gen_py.erc20 import ERC20

class ERC20H(MiliDoS):
    def __init__(self, network):
        super().__init__(network)
        self.TokenContract: ERC20 = None
        self.MasterContract: ERC20 = None

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
        self.TokenContract = ERC20(self.w3, self.TokenAddress).CallDebug(False).CallContractFee(10000000)
        self.MasterContract = ERC20(self.w3, self.ERC20Address).CallDebug(False).CallContractFee(10000000)