"""Generated wrapper for Eth2MultiDeposit Solidity contract."""

# pylint: disable=too-many-arguments

import json
from typing import (  # pylint: disable=unused-import
    Any,
    List,
    Optional,
    Tuple,
    Union,
)
import time
from eth_utils import to_checksum_address
from mypy_extensions import TypedDict  # pylint: disable=unused-import
from hexbytes import HexBytes
from web3 import Web3
from web3.contract import ContractFunction
from web3.datastructures import AttributeDict
from web3.providers.base import BaseProvider
from web3.exceptions import ContractLogicError
from moody.m.bases import ContractMethod, Validator, ContractBase, Signatures
from moody.m.tx_params import TxParams
from moody.libeb import MiliDoS
from moody import Bolors

# Try to import a custom validator class definition; if there isn't one,
# declare one that we can instantiate for the default argument to the
# constructor for Eth2MultiDeposit below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        Eth2MultiDepositValidator,
    )
except ImportError:

    class Eth2MultiDepositValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class DepositMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the deposit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("deposit")

    def validate_and_normalize_inputs(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]]) -> any:
        """Validate the inputs to the deposit method."""
        self.validator.assert_valid(
            method_name='deposit',
            parameter_name='pubkey',
            argument_value=pubkey,
        )
        self.validator.assert_valid(
            method_name='deposit',
            parameter_name='withdrawal_credentials',
            argument_value=withdrawal_credentials,
        )
        self.validator.assert_valid(
            method_name='deposit',
            parameter_name='signature',
            argument_value=signature,
        )
        self.validator.assert_valid(
            method_name='deposit',
            parameter_name='deposit_data_root',
            argument_value=deposit_data_root,
        )
        return (pubkey, withdrawal_credentials, signature, deposit_data_root)

    def block_send(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]], _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(pubkey, withdrawal_credentials, signature, deposit_data_root)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': _gaswei,
                'gasPrice': _pricewei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if _debugtx:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if _receipList is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if _debugtx:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET} - broadcast hash")

            if _receipList is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: deposit")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, deposit: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, deposit. Reason: Unknown")

    def send_transaction(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (pubkey, withdrawal_credentials, signature, deposit_data_root) = self.validate_and_normalize_inputs(pubkey, withdrawal_credentials, signature, deposit_data_root)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pubkey, withdrawal_credentials, signature, deposit_data_root).transact(tx_params.as_dict())

    def build_transaction(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (pubkey, withdrawal_credentials, signature, deposit_data_root) = self.validate_and_normalize_inputs(pubkey, withdrawal_credentials, signature, deposit_data_root)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pubkey, withdrawal_credentials, signature, deposit_data_root).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (pubkey, withdrawal_credentials, signature, deposit_data_root) = self.validate_and_normalize_inputs(pubkey, withdrawal_credentials, signature, deposit_data_root)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pubkey, withdrawal_credentials, signature, deposit_data_root).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def deposit(self) -> str:
        return self._function_signatures["deposit"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Eth2MultiDeposit(ContractBase):
    """Wrapper class for Eth2MultiDeposit Solidity contract."""
    _fn_deposit: DepositMethod
    """Constructor-initialized instance of
    :class:`DepositMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: Eth2MultiDepositValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = Eth2MultiDepositValidator(web3, contract_address)

        # if any middleware was imported, inject it
        try:
            MIDDLEWARE
        except NameError:
            pass
        else:
            try:
                for middleware in MIDDLEWARE:
                    web3.middleware_onion.inject(
                        middleware['function'], layer=middleware['layer'],
                    )
            except ValueError as value_error:
                if value_error.args == ("You can't add the same un-named instance twice",):
                    pass

        self._web3_eth = web3.eth
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Eth2MultiDeposit.abi()).functions
        signed = SignatureGenerator(Eth2MultiDeposit.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_deposit = DepositMethod(core_lib, contract_address, functions.deposit, validator)

    def deposit(self, pubkey: List[Union[bytes, str]], withdrawal_credentials: List[Union[bytes, str]], signature: List[Union[bytes, str]], deposit_data_root: List[Union[bytes, str]], wei: int = 0) -> None:
        """
        Implementation of deposit in contract Eth2MultiDeposit
        Method of the function
    
    
    
        """

        return self._fn_deposit.block_send(pubkey, withdrawal_credentials, signature, deposit_data_root, self.call_contract_fee_amount, self.call_contract_fee_price, wei, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def CallContractWait(self, t_long: int) -> "Eth2MultiDeposit":
        self._fn_deposit.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"bytes[]","name":"pubkey","type":"bytes[]"},{"internalType":"bytes[]","name":"withdrawal_credentials","type":"bytes[]"},{"internalType":"bytes[]","name":"signature","type":"bytes[]"},{"internalType":"bytes32[]","name":"deposit_data_root","type":"bytes32[]"}],"name":"deposit","outputs":[],"stateMutability":"payable","type":"function"}]'  # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
