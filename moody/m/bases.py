"""Base wrapper class for accessing ethereum smart contracts."""

from typing import Any

from eth_utils import is_address, to_checksum_address

from web3 import Web3

from .tx_params import TxParams
# from web3.providers.base import BaseProvider
from ..libeb import MiliDoS
from .. import Bolors


class Signatures:
    _function_signatures = {}

    def __init__(self, abi: any):
        for func in [obj for obj in abi if obj['type'] == 'function']:
            name = func['name']
            types = [input['type'] for input in func['inputs']]
            self._function_signatures[name] = '{}({})'.format(name, ','.join(types))
        self._abi_store = abi

    def fromSignatures(self) -> dict:
        return self._function_signatures


class Validator:
    """Base class for validating inputs to methods."""
    address = ""

    def __init__(
            self,
            web3_or_provider: Web3,
            contract_address: str,
    ):
        """Initialize the instance."""
        self.address = contract_address

    def assert_valid(
            self, method_name: str, parameter_name: str, argument_value: Any
    ):
        """Raise an exception if method input is not valid.

        :param method_name: Name of the method whose input is to be validated.
        :param parameter_name: Name of the parameter whose input is to be
            validated.
        :param argument_value: Value of argument to parameter to be validated.
        """

    def bindSignatures(self, so: Signatures) -> None:
        self._bind_singatures = so

    def getSignature(self, sign_name: str) -> str:
        return self._bind_singatures.fromSignatures()[sign_name]


class ContractMethod:
    """Base class for wrapping an Ethereum smart contract method."""

    def __init__(
            self,
            elib: MiliDoS,
            contract_address: str,
            validator: Validator = None,
    ):
        """Instantiate the object.

        :param provider: Instance of :class:`web3.providers.base.BaseProvider`
        :param contract_address: Where the contract has been deployed to.
        :param validator: Used to validate method inputs.
        """

        self._web3_eth = elib.w3.eth  # pylint: disable=no-member
        if validator is None:
            validator = Validator(self._web3_eth, contract_address)
        self.validator = validator
        self._operate = elib.accountAddr
        self._wait = 5
        self.wei_value = 0
        self.gas_limit = 0
        self.gas_price_wei = 0
        self.auto_reciept = False
        self.debug_method = False
        self.callback_onsuccess = None
        self.callback_onfail = None

    @staticmethod
    def validate_and_checksum_address(address: str):
        """Validate the given address, and return it's checksum address."""
        if not is_address(address):
            raise TypeError("Invalid address provided: {}".format(address))
        return to_checksum_address(address)

    def normalize_tx_params(self, tx_params) -> TxParams:
        """Normalize and return the given transaction parameters."""
        if not tx_params:
            tx_params = TxParams()
        if not tx_params.from_:
            tx_params.from_ = self._web3_eth.coinbase or (
                self._web3_eth.accounts[0]
                if len(self._web3_eth.accounts) > 0
                else None
            )
        if tx_params.from_:
            tx_params.from_ = self.validate_and_checksum_address(
                tx_params.from_
            )
        return tx_params

    def setWait(self, t: int) -> "ContractMethod":
        self._wait = t
        return self

    def _on_receipt_handle(self, method_name: str, receipt=None, boardcast_hash=None) -> None:
        print(f"======== TX blockHash ✅")
        if receipt is not None:
            print(f"{Bolors.OK}{receipt.blockHash.hex()}{Bolors.RESET}")
            if self.callback_onsuccess is not None:
                self.callback_onsuccess(receipt.blockHash.hex(), method_name)
        else:
            if boardcast_hash is not None:
                print(f"{Bolors.WARNING}{boardcast_hash.hex()}{Bolors.RESET} - broadcast hash")

    def _on_fail(self, name: str, message: str) -> None:
        if self.callback_onfail is not None:
            self.callback_onfail(name, message)


"""
https://ethereum.stackexchange.com/questions/65037/web3py-encode-method-call-parameters

def getInfo(abi, address):
    api = w3.eth.contract(address=address, abi=abi)
    return api


def contractFunction(address, param1, param2):
    abi = 
            json abi code   
          
    return getInfo(abi, address).functions.contractFunction(param1, param2)


def get_data_ex() -> str:
    return str(contractFunction(contract, param1, param2).selector)
    + param1.rjust(64, '0')
    + param2.rjust(64, '0')
    
There contract is first 4 symbols of hash contract function with parameter, and other symbols is symbols, appended to 64 symbols with 0
    
"""


class ContractBase:

    def __init__(self, address: str, abi: any):
        self.call_contract_fee_amount: int = 2000000000
        self.call_contract_fee_price: int = 105910000000
        self.call_contract_debug_flag: bool = False
        self.call_contract_enforce_tx_receipt: bool = True
        self.contract_address = address
        self._callback_onsuccess = None
        self._callback_onfail = None
        self._abi_store = abi
        self._signatures = None

    @property
    def fromAbi(self) -> any:
        return self._abi_store

    def CallAutoConf(self, f: MiliDoS) -> "ContractBase":
        self.call_contract_fee_amount = f.gas
        self.call_contract_fee_price = f.gasPrice
        return self

    def CallContractFee(self, gas: int, price: int) -> "ContractBase":
        self.call_contract_fee_amount = gas
        self.call_contract_fee_price = price
        return self

    def CallDebug(self, yesno: bool) -> "ContractBase":
        self.call_contract_debug_flag = yesno
        return self

    def EnforceTxReceipt(self, yesno: bool) -> "ContractBase":
        self.call_contract_enforce_tx_receipt = yesno
        return self

    def onSuccssCallback(self, cb: any) -> "ContractBase":
        self._callback_onsuccess = cb
        return self

    def onFailCallback(self, cb: any) -> "ContractBase":
        self._callback_onfail = cb
        return self

    def CallSignature(self) -> Signatures:
        return self._signatures
