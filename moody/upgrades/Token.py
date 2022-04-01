from .. import Token
from ..libeb import MiliDoS
from ..m.tc20 import Tc20


class TokenActor(Token):
    """
    Preforming an upgrade contract to the previous contract
    """

    def __init__(self, _from: MiliDoS):
        self.engine: MiliDoS = _from
        self._token: Tc20

    @property
    def TokenAddress(self) -> str:
        if self.engine.hasContractName("Tc20"):
            return self.engine.getAddr("Tc20")
        elif self.engine.hasContractName("Ori20"):
            return self.engine.getAddr("Ori20")
        elif self.engine.hasContractName("Erc20"):
            return self.engine.getAddr("Erc20")
        else:
            raise ValueError("🛑 token contract address is not found")

    def conf(self, tokenNameOrAddress: str = None) -> "TokenActor":
        head = tokenNameOrAddress[:2]
        address = ""
        if head == "0x":
            address = tokenNameOrAddress
        elif self.engine.hasContractName(tokenNameOrAddress):
            address = self.engine.getAddr(tokenNameOrAddress)
        else:
            print("⚠️ Since there is no given token address, we will fail back and select the default NameClass Tc20/Ori20/Erc20")
            address = self.TokenAddress

        self._token = Tc20(self.engine, address)
        self._token.CallContractFee(self.engine.gas, self.engine.gasPrice).CallDebug(True).CallContractWait(self.engine.waitSec)
        return self

    def addMinter(self, who: str) -> None:
        self._token.add_minter(who)

    def issueCoin(self, benefit: str, count: int) -> None:
        self._token.mint(benefit, count)

    def issueCoinWithBase(self, benefit: str, one: int) -> None:
        self._token.mint(benefit, one * self.engine.one)

    def removeMinter(self, whom: str) -> None:
        self._token.remove_minter(whom)

    def balanceCheck(self, whom: str) -> int:
        return self._token.balance_of(whom)

    def approve(self, whom_spender: str, amount: int) -> bool:
        return self._token.approve(whom_spender, amount)

    def allowance(self, owner: str, spender: str) -> int:
        return self._token.allowance(owner, spender)

    def transfer(self, owner: str, amount: int) -> bool:
        return self._token.transfer(owner, amount)
