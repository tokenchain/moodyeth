"""Generated wrapper for pharaohs Solidity contract."""

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
# constructor for pharaohs below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        pharaohsValidator,
    )
except ImportError:

    class pharaohsValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class DelegationTypehashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the DELEGATION_TYPEHASH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("DELEGATION_TYPEHASH")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class DomainTypehashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the DOMAIN_TYPEHASH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("DOMAIN_TYPEHASH")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class PermitTypehashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the PERMIT_TYPEHASH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("PERMIT_TYPEHASH")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class AllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the allowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("allowance")

    def validate_and_normalize_inputs(self, account: str, spender: str) -> any:
        """Validate the inputs to the allowance method."""
        self.validator.assert_valid(
            method_name='allowance',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        self.validator.assert_valid(
            method_name='allowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        return (account, spender)

    def block_call(self, account: str, spender: str, debug: bool = False) -> int:
        _fn = self._underlying_method(account, spender)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, account: str, spender: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account, spender) = self.validate_and_normalize_inputs(account, spender)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, spender).estimateGas(tx_params.as_dict())


class ApproveMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the approve method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("approve")

    def validate_and_normalize_inputs(self, spender: str, raw_amount: int) -> any:
        """Validate the inputs to the approve method."""
        self.validator.assert_valid(
            method_name='approve',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='approve',
            parameter_name='rawAmount',
            argument_value=raw_amount,
        )
        # safeguard against fractional inputs
        raw_amount = int(raw_amount)
        return (spender, raw_amount)

    def block_send(self, spender: str, raw_amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(spender, raw_amount)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("approve", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: approve")
            message = f"Error {er}: approve"
            self._on_fail("approve", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, approve: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, approve. Reason: Unknown")

            self._on_fail("approve", message)

    def send_transaction(self, spender: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, raw_amount) = self.validate_and_normalize_inputs(spender, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, raw_amount).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, raw_amount) = self.validate_and_normalize_inputs(spender, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, raw_amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, raw_amount) = self.validate_and_normalize_inputs(spender, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, raw_amount).estimateGas(tx_params.as_dict())


class BalanceOfMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the balanceOf method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("balanceOf")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the balanceOf method."""
        self.validator.assert_valid(
            method_name='balanceOf',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, debug: bool = False) -> int:
        _fn = self._underlying_method(account)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class CheckpointsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the checkpoints method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("checkpoints")

    def validate_and_normalize_inputs(self, index_0: str, index_1: int) -> any:
        """Validate the inputs to the checkpoints method."""
        self.validator.assert_valid(
            method_name='checkpoints',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        self.validator.assert_valid(
            method_name='checkpoints',
            parameter_name='index_1',
            argument_value=index_1,
        )
        return (index_0, index_1)

    def block_call(self, index_0: str, index_1: int, debug: bool = False) -> Tuple[int, int]:
        _fn = self._underlying_method(index_0, index_1)
        returned = _fn.call({
            'from': self._operate
        })
        return (returned[0], returned[1],)

    def estimate_gas(self, index_0: str, index_1: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0, index_1) = self.validate_and_normalize_inputs(index_0, index_1)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0, index_1).estimateGas(tx_params.as_dict())


class DecimalsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the decimals method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("decimals")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class DelegateMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the delegate method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("delegate")

    def validate_and_normalize_inputs(self, delegatee: str) -> any:
        """Validate the inputs to the delegate method."""
        self.validator.assert_valid(
            method_name='delegate',
            parameter_name='delegatee',
            argument_value=delegatee,
        )
        delegatee = self.validate_and_checksum_address(delegatee)
        return (delegatee)

    def block_send(self, delegatee: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(delegatee)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("delegate", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: delegate")
            message = f"Error {er}: delegate"
            self._on_fail("delegate", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, delegate: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, delegate. Reason: Unknown")

            self._on_fail("delegate", message)

    def send_transaction(self, delegatee: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (delegatee) = self.validate_and_normalize_inputs(delegatee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee).transact(tx_params.as_dict())

    def build_transaction(self, delegatee: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (delegatee) = self.validate_and_normalize_inputs(delegatee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, delegatee: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (delegatee) = self.validate_and_normalize_inputs(delegatee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee).estimateGas(tx_params.as_dict())


class DelegateBySigMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the delegateBySig method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("delegateBySig")

    def validate_and_normalize_inputs(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> any:
        """Validate the inputs to the delegateBySig method."""
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='delegatee',
            argument_value=delegatee,
        )
        delegatee = self.validate_and_checksum_address(delegatee)
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='nonce',
            argument_value=nonce,
        )
        # safeguard against fractional inputs
        nonce = int(nonce)
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='expiry',
            argument_value=expiry,
        )
        # safeguard against fractional inputs
        expiry = int(expiry)
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='v',
            argument_value=v,
        )
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='r',
            argument_value=r,
        )
        self.validator.assert_valid(
            method_name='delegateBySig',
            parameter_name='s',
            argument_value=s,
        )
        return (delegatee, nonce, expiry, v, r, s)

    def block_send(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str], _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(delegatee, nonce, expiry, v, r, s)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("delegate_by_sig", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: delegate_by_sig")
            message = f"Error {er}: delegate_by_sig"
            self._on_fail("delegate_by_sig", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, delegate_by_sig: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, delegate_by_sig. Reason: Unknown")

            self._on_fail("delegate_by_sig", message)

    def send_transaction(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (delegatee, nonce, expiry, v, r, s) = self.validate_and_normalize_inputs(delegatee, nonce, expiry, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee, nonce, expiry, v, r, s).transact(tx_params.as_dict())

    def build_transaction(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (delegatee, nonce, expiry, v, r, s) = self.validate_and_normalize_inputs(delegatee, nonce, expiry, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee, nonce, expiry, v, r, s).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (delegatee, nonce, expiry, v, r, s) = self.validate_and_normalize_inputs(delegatee, nonce, expiry, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delegatee, nonce, expiry, v, r, s).estimateGas(tx_params.as_dict())


class DelegatesMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the delegates method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("delegates")

    def validate_and_normalize_inputs(self, index_0: str) -> any:
        """Validate the inputs to the delegates method."""
        self.validator.assert_valid(
            method_name='delegates',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        return (index_0)

    def block_call(self, index_0: str, debug: bool = False) -> str:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def estimate_gas(self, index_0: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())


class GetCurrentVotesMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCurrentVotes method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCurrentVotes")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the getCurrentVotes method."""
        self.validator.assert_valid(
            method_name='getCurrentVotes',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, debug: bool = False) -> int:
        _fn = self._underlying_method(account)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class GetPriorVotesMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getPriorVotes method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getPriorVotes")

    def validate_and_normalize_inputs(self, account: str, block_number: int) -> any:
        """Validate the inputs to the getPriorVotes method."""
        self.validator.assert_valid(
            method_name='getPriorVotes',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        self.validator.assert_valid(
            method_name='getPriorVotes',
            parameter_name='blockNumber',
            argument_value=block_number,
        )
        # safeguard against fractional inputs
        block_number = int(block_number)
        return (account, block_number)

    def block_call(self, account: str, block_number: int, debug: bool = False) -> int:
        _fn = self._underlying_method(account, block_number)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, account: str, block_number: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account, block_number) = self.validate_and_normalize_inputs(account, block_number)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, block_number).estimateGas(tx_params.as_dict())


class NameMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the name method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("name")

    def block_call(self, debug: bool = False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class NoncesMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the nonces method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("nonces")

    def validate_and_normalize_inputs(self, index_0: str) -> any:
        """Validate the inputs to the nonces method."""
        self.validator.assert_valid(
            method_name='nonces',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        return (index_0)

    def block_call(self, index_0: str, debug: bool = False) -> int:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, index_0: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())


class NumCheckpointsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the numCheckpoints method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("numCheckpoints")

    def validate_and_normalize_inputs(self, index_0: str) -> any:
        """Validate the inputs to the numCheckpoints method."""
        self.validator.assert_valid(
            method_name='numCheckpoints',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        return (index_0)

    def block_call(self, index_0: str, debug: bool = False) -> int:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, index_0: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())


class PermitMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the permit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("permit")

    def validate_and_normalize_inputs(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> any:
        """Validate the inputs to the permit method."""
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='owner',
            argument_value=owner,
        )
        owner = self.validate_and_checksum_address(owner)
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='rawAmount',
            argument_value=raw_amount,
        )
        # safeguard against fractional inputs
        raw_amount = int(raw_amount)
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='v',
            argument_value=v,
        )
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='r',
            argument_value=r,
        )
        self.validator.assert_valid(
            method_name='permit',
            parameter_name='s',
            argument_value=s,
        )
        return (owner, spender, raw_amount, deadline, v, r, s)

    def block_send(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str], _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(owner, spender, raw_amount, deadline, v, r, s)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("permit", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: permit")
            message = f"Error {er}: permit"
            self._on_fail("permit", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, permit: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, permit. Reason: Unknown")

            self._on_fail("permit", message)

    def send_transaction(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (owner, spender, raw_amount, deadline, v, r, s) = self.validate_and_normalize_inputs(owner, spender, raw_amount, deadline, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner, spender, raw_amount, deadline, v, r, s).transact(tx_params.as_dict())

    def build_transaction(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (owner, spender, raw_amount, deadline, v, r, s) = self.validate_and_normalize_inputs(owner, spender, raw_amount, deadline, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner, spender, raw_amount, deadline, v, r, s).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (owner, spender, raw_amount, deadline, v, r, s) = self.validate_and_normalize_inputs(owner, spender, raw_amount, deadline, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner, spender, raw_amount, deadline, v, r, s).estimateGas(tx_params.as_dict())


class SymbolMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the symbol method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("symbol")

    def block_call(self, debug: bool = False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class TotalSupplyMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the totalSupply method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("totalSupply")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class TransferMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transfer method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("transfer")

    def validate_and_normalize_inputs(self, dst: str, raw_amount: int) -> any:
        """Validate the inputs to the transfer method."""
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='dst',
            argument_value=dst,
        )
        dst = self.validate_and_checksum_address(dst)
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='rawAmount',
            argument_value=raw_amount,
        )
        # safeguard against fractional inputs
        raw_amount = int(raw_amount)
        return (dst, raw_amount)

    def block_send(self, dst: str, raw_amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(dst, raw_amount)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("transfer", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer")
            message = f"Error {er}: transfer"
            self._on_fail("transfer", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer. Reason: Unknown")

            self._on_fail("transfer", message)

    def send_transaction(self, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (dst, raw_amount) = self.validate_and_normalize_inputs(dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, raw_amount).transact(tx_params.as_dict())

    def build_transaction(self, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (dst, raw_amount) = self.validate_and_normalize_inputs(dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, raw_amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (dst, raw_amount) = self.validate_and_normalize_inputs(dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, raw_amount).estimateGas(tx_params.as_dict())


class TransferFromMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transferFrom method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("transferFrom")

    def validate_and_normalize_inputs(self, src: str, dst: str, raw_amount: int) -> any:
        """Validate the inputs to the transferFrom method."""
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='src',
            argument_value=src,
        )
        src = self.validate_and_checksum_address(src)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='dst',
            argument_value=dst,
        )
        dst = self.validate_and_checksum_address(dst)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='rawAmount',
            argument_value=raw_amount,
        )
        # safeguard against fractional inputs
        raw_amount = int(raw_amount)
        return (src, dst, raw_amount)

    def block_send(self, src: str, dst: str, raw_amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(src, dst, raw_amount)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': self.gas_limit,
                'gasPrice': self.gas_price_wei
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if _valeth > 0:
                _t['value'] = _valeth

            if self.debug_method:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if self.auto_reciept is True:
                    print(f"======== awaiting Confirmation 🚸️ {self.sign}")
                    tx_receipt = self._web3_eth.wait_for_transaction_receipt(txHash)
                    if self.debug_method:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                self._on_receipt_handle("transfer_from", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer_from")
            message = f"Error {er}: transfer_from"
            self._on_fail("transfer_from", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_from: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_from. Reason: Unknown")

            self._on_fail("transfer_from", message)

    def send_transaction(self, src: str, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (src, dst, raw_amount) = self.validate_and_normalize_inputs(src, dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, raw_amount).transact(tx_params.as_dict())

    def build_transaction(self, src: str, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (src, dst, raw_amount) = self.validate_and_normalize_inputs(src, dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, raw_amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, src: str, dst: str, raw_amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (src, dst, raw_amount) = self.validate_and_normalize_inputs(src, dst, raw_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, raw_amount).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def delegation_typehash(self) -> str:
        return self._function_signatures["DELEGATION_TYPEHASH"]

    def domain_typehash(self) -> str:
        return self._function_signatures["DOMAIN_TYPEHASH"]

    def permit_typehash(self) -> str:
        return self._function_signatures["PERMIT_TYPEHASH"]

    def allowance(self) -> str:
        return self._function_signatures["allowance"]

    def approve(self) -> str:
        return self._function_signatures["approve"]

    def balance_of(self) -> str:
        return self._function_signatures["balanceOf"]

    def checkpoints(self) -> str:
        return self._function_signatures["checkpoints"]

    def decimals(self) -> str:
        return self._function_signatures["decimals"]

    def delegate(self) -> str:
        return self._function_signatures["delegate"]

    def delegate_by_sig(self) -> str:
        return self._function_signatures["delegateBySig"]

    def delegates(self) -> str:
        return self._function_signatures["delegates"]

    def get_current_votes(self) -> str:
        return self._function_signatures["getCurrentVotes"]

    def get_prior_votes(self) -> str:
        return self._function_signatures["getPriorVotes"]

    def name(self) -> str:
        return self._function_signatures["name"]

    def nonces(self) -> str:
        return self._function_signatures["nonces"]

    def num_checkpoints(self) -> str:
        return self._function_signatures["numCheckpoints"]

    def permit(self) -> str:
        return self._function_signatures["permit"]

    def symbol(self) -> str:
        return self._function_signatures["symbol"]

    def total_supply(self) -> str:
        return self._function_signatures["totalSupply"]

    def transfer(self) -> str:
        return self._function_signatures["transfer"]

    def transfer_from(self) -> str:
        return self._function_signatures["transferFrom"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class pharaohs(ContractBase):
    """Wrapper class for pharaohs Solidity contract."""
    _fn_delegation_typehash: DelegationTypehashMethod
    """Constructor-initialized instance of
    :class:`DelegationTypehashMethod`.
    """

    _fn_domain_typehash: DomainTypehashMethod
    """Constructor-initialized instance of
    :class:`DomainTypehashMethod`.
    """

    _fn_permit_typehash: PermitTypehashMethod
    """Constructor-initialized instance of
    :class:`PermitTypehashMethod`.
    """

    _fn_allowance: AllowanceMethod
    """Constructor-initialized instance of
    :class:`AllowanceMethod`.
    """

    _fn_approve: ApproveMethod
    """Constructor-initialized instance of
    :class:`ApproveMethod`.
    """

    _fn_balance_of: BalanceOfMethod
    """Constructor-initialized instance of
    :class:`BalanceOfMethod`.
    """

    _fn_checkpoints: CheckpointsMethod
    """Constructor-initialized instance of
    :class:`CheckpointsMethod`.
    """

    _fn_decimals: DecimalsMethod
    """Constructor-initialized instance of
    :class:`DecimalsMethod`.
    """

    _fn_delegate: DelegateMethod
    """Constructor-initialized instance of
    :class:`DelegateMethod`.
    """

    _fn_delegate_by_sig: DelegateBySigMethod
    """Constructor-initialized instance of
    :class:`DelegateBySigMethod`.
    """

    _fn_delegates: DelegatesMethod
    """Constructor-initialized instance of
    :class:`DelegatesMethod`.
    """

    _fn_get_current_votes: GetCurrentVotesMethod
    """Constructor-initialized instance of
    :class:`GetCurrentVotesMethod`.
    """

    _fn_get_prior_votes: GetPriorVotesMethod
    """Constructor-initialized instance of
    :class:`GetPriorVotesMethod`.
    """

    _fn_name: NameMethod
    """Constructor-initialized instance of
    :class:`NameMethod`.
    """

    _fn_nonces: NoncesMethod
    """Constructor-initialized instance of
    :class:`NoncesMethod`.
    """

    _fn_num_checkpoints: NumCheckpointsMethod
    """Constructor-initialized instance of
    :class:`NumCheckpointsMethod`.
    """

    _fn_permit: PermitMethod
    """Constructor-initialized instance of
    :class:`PermitMethod`.
    """

    _fn_symbol: SymbolMethod
    """Constructor-initialized instance of
    :class:`SymbolMethod`.
    """

    _fn_total_supply: TotalSupplyMethod
    """Constructor-initialized instance of
    :class:`TotalSupplyMethod`.
    """

    _fn_transfer: TransferMethod
    """Constructor-initialized instance of
    :class:`TransferMethod`.
    """

    _fn_transfer_from: TransferFromMethod
    """Constructor-initialized instance of
    :class:`TransferFromMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: pharaohsValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, pharaohs.abi())
        web3 = core_lib.w3

        if not validator:
            validator = pharaohsValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=pharaohs.abi()).functions
        self._signatures = SignatureGenerator(pharaohs.abi())
        validator.bindSignatures(self._signatures)

        self._fn_delegation_typehash = DelegationTypehashMethod(core_lib, contract_address, functions.DELEGATION_TYPEHASH, validator)
        self._fn_domain_typehash = DomainTypehashMethod(core_lib, contract_address, functions.DOMAIN_TYPEHASH, validator)
        self._fn_permit_typehash = PermitTypehashMethod(core_lib, contract_address, functions.PERMIT_TYPEHASH, validator)
        self._fn_allowance = AllowanceMethod(core_lib, contract_address, functions.allowance, validator)
        self._fn_approve = ApproveMethod(core_lib, contract_address, functions.approve, validator)
        self._fn_balance_of = BalanceOfMethod(core_lib, contract_address, functions.balanceOf, validator)
        self._fn_checkpoints = CheckpointsMethod(core_lib, contract_address, functions.checkpoints, validator)
        self._fn_decimals = DecimalsMethod(core_lib, contract_address, functions.decimals, validator)
        self._fn_delegate = DelegateMethod(core_lib, contract_address, functions.delegate, validator)
        self._fn_delegate_by_sig = DelegateBySigMethod(core_lib, contract_address, functions.delegateBySig, validator)
        self._fn_delegates = DelegatesMethod(core_lib, contract_address, functions.delegates, validator)
        self._fn_get_current_votes = GetCurrentVotesMethod(core_lib, contract_address, functions.getCurrentVotes, validator)
        self._fn_get_prior_votes = GetPriorVotesMethod(core_lib, contract_address, functions.getPriorVotes, validator)
        self._fn_name = NameMethod(core_lib, contract_address, functions.name, validator)
        self._fn_nonces = NoncesMethod(core_lib, contract_address, functions.nonces, validator)
        self._fn_num_checkpoints = NumCheckpointsMethod(core_lib, contract_address, functions.numCheckpoints, validator)
        self._fn_permit = PermitMethod(core_lib, contract_address, functions.permit, validator)
        self._fn_symbol = SymbolMethod(core_lib, contract_address, functions.symbol, validator)
        self._fn_total_supply = TotalSupplyMethod(core_lib, contract_address, functions.totalSupply, validator)
        self._fn_transfer = TransferMethod(core_lib, contract_address, functions.transfer, validator)
        self._fn_transfer_from = TransferFromMethod(core_lib, contract_address, functions.transferFrom, validator)

    def event_approval(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event approval in contract pharaohs
        Get log entry for Approval event.
                :param tx_hash: hash of transaction emitting Approval event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=pharaohs.abi()).events.Approval().processReceipt(tx_receipt)

    def event_delegate_changed(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event delegate_changed in contract pharaohs
        Get log entry for DelegateChanged event.
                :param tx_hash: hash of transaction emitting DelegateChanged event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=pharaohs.abi()).events.DelegateChanged().processReceipt(tx_receipt)

    def event_delegate_votes_changed(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event delegate_votes_changed in contract pharaohs
        Get log entry for DelegateVotesChanged event.
                :param tx_hash: hash of transaction emitting DelegateVotesChanged event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=pharaohs.abi()).events.DelegateVotesChanged().processReceipt(tx_receipt)

    def event_transfer(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event transfer in contract pharaohs
        Get log entry for Transfer event.
                :param tx_hash: hash of transaction emitting Transfer event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=pharaohs.abi()).events.Transfer().processReceipt(tx_receipt)

    def delegation_typehash(self) -> Union[bytes, str]:
        """
        Implementation of delegation_typehash in contract pharaohs
        Method of the function

        """

        self._fn_delegation_typehash.callback_onfail = self._callback_onfail
        self._fn_delegation_typehash.callback_onsuccess = self._callback_onsuccess
        self._fn_delegation_typehash.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_delegation_typehash.gas_limit = self.call_contract_fee_amount
        self._fn_delegation_typehash.gas_price_wei = self.call_contract_fee_price
        self._fn_delegation_typehash.debug_method = self.call_contract_debug_flag

        return self._fn_delegation_typehash.block_call()

    def domain_typehash(self) -> Union[bytes, str]:
        """
        Implementation of domain_typehash in contract pharaohs
        Method of the function

        """

        self._fn_domain_typehash.callback_onfail = self._callback_onfail
        self._fn_domain_typehash.callback_onsuccess = self._callback_onsuccess
        self._fn_domain_typehash.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_domain_typehash.gas_limit = self.call_contract_fee_amount
        self._fn_domain_typehash.gas_price_wei = self.call_contract_fee_price
        self._fn_domain_typehash.debug_method = self.call_contract_debug_flag

        return self._fn_domain_typehash.block_call()

    def permit_typehash(self) -> Union[bytes, str]:
        """
        Implementation of permit_typehash in contract pharaohs
        Method of the function

        """

        self._fn_permit_typehash.callback_onfail = self._callback_onfail
        self._fn_permit_typehash.callback_onsuccess = self._callback_onsuccess
        self._fn_permit_typehash.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_permit_typehash.gas_limit = self.call_contract_fee_amount
        self._fn_permit_typehash.gas_price_wei = self.call_contract_fee_price
        self._fn_permit_typehash.debug_method = self.call_contract_debug_flag

        return self._fn_permit_typehash.block_call()

    def allowance(self, account: str, spender: str) -> int:
        """
        Implementation of allowance in contract pharaohs
        Method of the function

        """

        self._fn_allowance.callback_onfail = self._callback_onfail
        self._fn_allowance.callback_onsuccess = self._callback_onsuccess
        self._fn_allowance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_allowance.gas_limit = self.call_contract_fee_amount
        self._fn_allowance.gas_price_wei = self.call_contract_fee_price
        self._fn_allowance.debug_method = self.call_contract_debug_flag

        return self._fn_allowance.block_call(account, spender)

    def approve(self, spender: str, raw_amount: int) -> bool:
        """
        Implementation of approve in contract pharaohs
        Method of the function

        """

        self._fn_approve.callback_onfail = self._callback_onfail
        self._fn_approve.callback_onsuccess = self._callback_onsuccess
        self._fn_approve.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_approve.gas_limit = self.call_contract_fee_amount
        self._fn_approve.gas_price_wei = self.call_contract_fee_price
        self._fn_approve.debug_method = self.call_contract_debug_flag

        return self._fn_approve.block_send(spender, raw_amount)

    def balance_of(self, account: str) -> int:
        """
        Implementation of balance_of in contract pharaohs
        Method of the function

        """

        self._fn_balance_of.callback_onfail = self._callback_onfail
        self._fn_balance_of.callback_onsuccess = self._callback_onsuccess
        self._fn_balance_of.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_balance_of.gas_limit = self.call_contract_fee_amount
        self._fn_balance_of.gas_price_wei = self.call_contract_fee_price
        self._fn_balance_of.debug_method = self.call_contract_debug_flag

        return self._fn_balance_of.block_call(account)

    def checkpoints(self, index_0: str, index_1: int) -> Tuple[int, int]:
        """
        Implementation of checkpoints in contract pharaohs
        Method of the function

        """

        self._fn_checkpoints.callback_onfail = self._callback_onfail
        self._fn_checkpoints.callback_onsuccess = self._callback_onsuccess
        self._fn_checkpoints.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_checkpoints.gas_limit = self.call_contract_fee_amount
        self._fn_checkpoints.gas_price_wei = self.call_contract_fee_price
        self._fn_checkpoints.debug_method = self.call_contract_debug_flag

        return self._fn_checkpoints.block_call(index_0, index_1)

    def decimals(self) -> int:
        """
        Implementation of decimals in contract pharaohs
        Method of the function

        """

        self._fn_decimals.callback_onfail = self._callback_onfail
        self._fn_decimals.callback_onsuccess = self._callback_onsuccess
        self._fn_decimals.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_decimals.gas_limit = self.call_contract_fee_amount
        self._fn_decimals.gas_price_wei = self.call_contract_fee_price
        self._fn_decimals.debug_method = self.call_contract_debug_flag

        return self._fn_decimals.block_call()

    def delegate(self, delegatee: str) -> None:
        """
        Implementation of delegate in contract pharaohs
        Method of the function

        """

        self._fn_delegate.callback_onfail = self._callback_onfail
        self._fn_delegate.callback_onsuccess = self._callback_onsuccess
        self._fn_delegate.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_delegate.gas_limit = self.call_contract_fee_amount
        self._fn_delegate.gas_price_wei = self.call_contract_fee_price
        self._fn_delegate.debug_method = self.call_contract_debug_flag

        return self._fn_delegate.block_send(delegatee)

    def delegate_by_sig(self, delegatee: str, nonce: int, expiry: int, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> None:
        """
        Implementation of delegate_by_sig in contract pharaohs
        Method of the function

        """

        self._fn_delegate_by_sig.callback_onfail = self._callback_onfail
        self._fn_delegate_by_sig.callback_onsuccess = self._callback_onsuccess
        self._fn_delegate_by_sig.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_delegate_by_sig.gas_limit = self.call_contract_fee_amount
        self._fn_delegate_by_sig.gas_price_wei = self.call_contract_fee_price
        self._fn_delegate_by_sig.debug_method = self.call_contract_debug_flag

        return self._fn_delegate_by_sig.block_send(delegatee, nonce, expiry, v, r, s)

    def delegates(self, index_0: str) -> str:
        """
        Implementation of delegates in contract pharaohs
        Method of the function

        """

        self._fn_delegates.callback_onfail = self._callback_onfail
        self._fn_delegates.callback_onsuccess = self._callback_onsuccess
        self._fn_delegates.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_delegates.gas_limit = self.call_contract_fee_amount
        self._fn_delegates.gas_price_wei = self.call_contract_fee_price
        self._fn_delegates.debug_method = self.call_contract_debug_flag

        return self._fn_delegates.block_call(index_0)

    def get_current_votes(self, account: str) -> int:
        """
        Implementation of get_current_votes in contract pharaohs
        Method of the function

        """

        self._fn_get_current_votes.callback_onfail = self._callback_onfail
        self._fn_get_current_votes.callback_onsuccess = self._callback_onsuccess
        self._fn_get_current_votes.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_current_votes.gas_limit = self.call_contract_fee_amount
        self._fn_get_current_votes.gas_price_wei = self.call_contract_fee_price
        self._fn_get_current_votes.debug_method = self.call_contract_debug_flag

        return self._fn_get_current_votes.block_call(account)

    def get_prior_votes(self, account: str, block_number: int) -> int:
        """
        Implementation of get_prior_votes in contract pharaohs
        Method of the function

        """

        self._fn_get_prior_votes.callback_onfail = self._callback_onfail
        self._fn_get_prior_votes.callback_onsuccess = self._callback_onsuccess
        self._fn_get_prior_votes.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_prior_votes.gas_limit = self.call_contract_fee_amount
        self._fn_get_prior_votes.gas_price_wei = self.call_contract_fee_price
        self._fn_get_prior_votes.debug_method = self.call_contract_debug_flag

        return self._fn_get_prior_votes.block_call(account, block_number)

    def name(self) -> str:
        """
        Implementation of name in contract pharaohs
        Method of the function

        """

        self._fn_name.callback_onfail = self._callback_onfail
        self._fn_name.callback_onsuccess = self._callback_onsuccess
        self._fn_name.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_name.gas_limit = self.call_contract_fee_amount
        self._fn_name.gas_price_wei = self.call_contract_fee_price
        self._fn_name.debug_method = self.call_contract_debug_flag

        return self._fn_name.block_call()

    def nonces(self, index_0: str) -> int:
        """
        Implementation of nonces in contract pharaohs
        Method of the function

        """

        self._fn_nonces.callback_onfail = self._callback_onfail
        self._fn_nonces.callback_onsuccess = self._callback_onsuccess
        self._fn_nonces.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_nonces.gas_limit = self.call_contract_fee_amount
        self._fn_nonces.gas_price_wei = self.call_contract_fee_price
        self._fn_nonces.debug_method = self.call_contract_debug_flag

        return self._fn_nonces.block_call(index_0)

    def num_checkpoints(self, index_0: str) -> int:
        """
        Implementation of num_checkpoints in contract pharaohs
        Method of the function

        """

        self._fn_num_checkpoints.callback_onfail = self._callback_onfail
        self._fn_num_checkpoints.callback_onsuccess = self._callback_onsuccess
        self._fn_num_checkpoints.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_num_checkpoints.gas_limit = self.call_contract_fee_amount
        self._fn_num_checkpoints.gas_price_wei = self.call_contract_fee_price
        self._fn_num_checkpoints.debug_method = self.call_contract_debug_flag

        return self._fn_num_checkpoints.block_call(index_0)

    def permit(self, owner: str, spender: str, raw_amount: int, deadline: int, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> None:
        """
        Implementation of permit in contract pharaohs
        Method of the function

        """

        self._fn_permit.callback_onfail = self._callback_onfail
        self._fn_permit.callback_onsuccess = self._callback_onsuccess
        self._fn_permit.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_permit.gas_limit = self.call_contract_fee_amount
        self._fn_permit.gas_price_wei = self.call_contract_fee_price
        self._fn_permit.debug_method = self.call_contract_debug_flag

        return self._fn_permit.block_send(owner, spender, raw_amount, deadline, v, r, s)

    def symbol(self) -> str:
        """
        Implementation of symbol in contract pharaohs
        Method of the function

        """

        self._fn_symbol.callback_onfail = self._callback_onfail
        self._fn_symbol.callback_onsuccess = self._callback_onsuccess
        self._fn_symbol.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_symbol.gas_limit = self.call_contract_fee_amount
        self._fn_symbol.gas_price_wei = self.call_contract_fee_price
        self._fn_symbol.debug_method = self.call_contract_debug_flag

        return self._fn_symbol.block_call()

    def total_supply(self) -> int:
        """
        Implementation of total_supply in contract pharaohs
        Method of the function

        """

        self._fn_total_supply.callback_onfail = self._callback_onfail
        self._fn_total_supply.callback_onsuccess = self._callback_onsuccess
        self._fn_total_supply.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_total_supply.gas_limit = self.call_contract_fee_amount
        self._fn_total_supply.gas_price_wei = self.call_contract_fee_price
        self._fn_total_supply.debug_method = self.call_contract_debug_flag

        return self._fn_total_supply.block_call()

    def transfer(self, dst: str, raw_amount: int) -> bool:
        """
        Implementation of transfer in contract pharaohs
        Method of the function

        """

        self._fn_transfer.callback_onfail = self._callback_onfail
        self._fn_transfer.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer.gas_limit = self.call_contract_fee_amount
        self._fn_transfer.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer.debug_method = self.call_contract_debug_flag

        return self._fn_transfer.block_send(dst, raw_amount)

    def transfer_from(self, src: str, dst: str, raw_amount: int) -> bool:
        """
        Implementation of transfer_from in contract pharaohs
        Method of the function

        """

        self._fn_transfer_from.callback_onfail = self._callback_onfail
        self._fn_transfer_from.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer_from.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer_from.gas_limit = self.call_contract_fee_amount
        self._fn_transfer_from.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer_from.debug_method = self.call_contract_debug_flag

        return self._fn_transfer_from.block_send(src, dst, raw_amount)

    def CallContractWait(self, t_long: int) -> "pharaohs":
        self._fn_delegation_typehash.setWait(t_long)
        self._fn_domain_typehash.setWait(t_long)
        self._fn_permit_typehash.setWait(t_long)
        self._fn_allowance.setWait(t_long)
        self._fn_approve.setWait(t_long)
        self._fn_balance_of.setWait(t_long)
        self._fn_checkpoints.setWait(t_long)
        self._fn_decimals.setWait(t_long)
        self._fn_delegate.setWait(t_long)
        self._fn_delegate_by_sig.setWait(t_long)
        self._fn_delegates.setWait(t_long)
        self._fn_get_current_votes.setWait(t_long)
        self._fn_get_prior_votes.setWait(t_long)
        self._fn_name.setWait(t_long)
        self._fn_nonces.setWait(t_long)
        self._fn_num_checkpoints.setWait(t_long)
        self._fn_permit.setWait(t_long)
        self._fn_symbol.setWait(t_long)
        self._fn_total_supply.setWait(t_long)
        self._fn_transfer.setWait(t_long)
        self._fn_transfer_from.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"account","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegator","type":"address"},{"indexed":true,"internalType":"address","name":"fromDelegate","type":"address"},{"indexed":true,"internalType":"address","name":"toDelegate","type":"address"}],"name":"DelegateChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegate","type":"address"},{"indexed":false,"internalType":"uint256","name":"previousBalance","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newBalance","type":"uint256"}],"name":"DelegateVotesChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":true,"inputs":[],"name":"DELEGATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"DOMAIN_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"PERMIT_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"index_0","type":"address"},{"internalType":"uint32","name":"index_1","type":"uint32"}],"name":"checkpoints","outputs":[{"internalType":"uint32","name":"fromBlock","type":"uint32"},{"internalType":"uint96","name":"votes","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"delegatee","type":"address"}],"name":"delegate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"delegatee","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"expiry","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"delegateBySig","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"index_0","type":"address"}],"name":"delegates","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"getCurrentVotes","outputs":[{"internalType":"uint96","name":"","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"blockNumber","type":"uint256"}],"name":"getPriorVotes","outputs":[{"internalType":"uint96","name":"","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"index_0","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"index_0","type":"address"}],"name":"numCheckpoints","outputs":[{"internalType":"uint32","name":"","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"src","type":"address"},{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
