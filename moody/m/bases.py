"""Base wrapper class for accessing ethereum smart contracts."""

from typing import Any

from eth_utils import is_address, to_checksum_address
from web3 import Web3

from .tx_params import TxParams
# from web3.providers.base import BaseProvider
from ..libeb import MiliDoS


class Signatures:
    _function_signatures = {}
    _abi_store = {}

    def __init__(self, abi: any):
        for func in [obj for obj in abi if obj['type'] == 'function']:
            name = func['name']
            types = [input['type'] for input in func['inputs']]
            self._function_signatures[name] = '{}({})'.format(name, ','.join(types))
        self._abi_store = abi

    def fromSignatures(self) -> dict:
        return self._function_signatures

    @property
    def fromAbi(self) -> any:
        return self._abi_store


class Validator:
    """Base class for validating inputs to methods."""

    def __init__(
            self,
            web3_or_provider: Web3,
            contract_address: str,
    ):
        """Initialize the instance."""
        pass

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
        self.binding: Signatures = so

    def getSignature(self, sign_name: str) -> str:
        return self.binding.fromSignatures()[sign_name]


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


class ContractBase:
    SIGNATURES: Signatures = None
    contract_address: str = None

    def __init__(self):
        self.call_contract_fee_amount: int = 2000000000
        self.call_contract_fee_price: int = 105910000000
        self.call_contract_debug_flag: bool = False
        self.call_contract_enforce_tx_receipt: bool = True

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

    def CallSignatureModel(self) -> Signatures:
        return self.SIGNATURES

