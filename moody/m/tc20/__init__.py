"""Generated wrapper for Tc20 Solidity contract."""

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
# constructor for Tc20 below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        Tc20Validator,
    )
except ImportError:

    class Tc20Validator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AddMinterMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addMinter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addMinter")

    def validate_and_normalize_inputs(self, minter: str) -> any:
        """Validate the inputs to the addMinter method."""
        self.validator.assert_valid(
            method_name='addMinter',
            parameter_name='_minter',
            argument_value=minter,
        )
        minter = self.validate_and_checksum_address(minter)
        return (minter)

    def block_send(self, minter: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(minter)
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

                self._on_receipt_handle("add_minter", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_minter")
            message = f"Error {er}: add_minter"
            self._on_fail("add_minter", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_minter: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_minter. Reason: Unknown")

            self._on_fail("add_minter", message)

    def send_transaction(self, minter: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).transact(tx_params.as_dict())

    def build_transaction(self, minter: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, minter: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).estimateGas(tx_params.as_dict())


class AllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the allowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("allowance")

    def validate_and_normalize_inputs(self, owner: str, spender: str) -> any:
        """Validate the inputs to the allowance method."""
        self.validator.assert_valid(
            method_name='allowance',
            parameter_name='owner',
            argument_value=owner,
        )
        owner = self.validate_and_checksum_address(owner)
        self.validator.assert_valid(
            method_name='allowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        return (owner, spender)

    def block_call(self, owner: str, spender: str, debug: bool = False) -> int:
        _fn = self._underlying_method(owner, spender)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, owner: str, spender: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (owner, spender) = self.validate_and_normalize_inputs(owner, spender)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner, spender).estimateGas(tx_params.as_dict())


class ApproveMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the approve method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("approve")

    def validate_and_normalize_inputs(self, spender: str, amount: int) -> any:
        """Validate the inputs to the approve method."""
        self.validator.assert_valid(
            method_name='approve',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='approve',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (spender, amount)

    def block_send(self, spender: str, amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(spender, amount)
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

    def send_transaction(self, spender: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, amount) = self.validate_and_normalize_inputs(spender, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, amount).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, amount) = self.validate_and_normalize_inputs(spender, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, amount) = self.validate_and_normalize_inputs(spender, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, amount).estimateGas(tx_params.as_dict())


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


class DecreaseAllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the decreaseAllowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("decreaseAllowance")

    def validate_and_normalize_inputs(self, spender: str, subtracted_value: int) -> any:
        """Validate the inputs to the decreaseAllowance method."""
        self.validator.assert_valid(
            method_name='decreaseAllowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='decreaseAllowance',
            parameter_name='subtractedValue',
            argument_value=subtracted_value,
        )
        # safeguard against fractional inputs
        subtracted_value = int(subtracted_value)
        return (spender, subtracted_value)

    def block_send(self, spender: str, subtracted_value: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(spender, subtracted_value)
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

                self._on_receipt_handle("decrease_allowance", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: decrease_allowance")
            message = f"Error {er}: decrease_allowance"
            self._on_fail("decrease_allowance", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, decrease_allowance: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, decrease_allowance. Reason: Unknown")

            self._on_fail("decrease_allowance", message)

    def send_transaction(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).estimateGas(tx_params.as_dict())


class GovernanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the governance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("governance")

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


class IncreaseAllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the increaseAllowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("increaseAllowance")

    def validate_and_normalize_inputs(self, spender: str, added_value: int) -> any:
        """Validate the inputs to the increaseAllowance method."""
        self.validator.assert_valid(
            method_name='increaseAllowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='increaseAllowance',
            parameter_name='addedValue',
            argument_value=added_value,
        )
        # safeguard against fractional inputs
        added_value = int(added_value)
        return (spender, added_value)

    def block_send(self, spender: str, added_value: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(spender, added_value)
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

                self._on_receipt_handle("increase_allowance", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: increase_allowance")
            message = f"Error {er}: increase_allowance"
            self._on_fail("increase_allowance", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, increase_allowance: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, increase_allowance. Reason: Unknown")

            self._on_fail("increase_allowance", message)

    def send_transaction(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).estimateGas(tx_params.as_dict())


class MintMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the mint method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("mint")

    def validate_and_normalize_inputs(self, account: str, amount: int) -> any:
        """Validate the inputs to the mint method."""
        self.validator.assert_valid(
            method_name='mint',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        self.validator.assert_valid(
            method_name='mint',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (account, amount)

    def block_send(self, account: str, amount: int, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account, amount)
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

                self._on_receipt_handle("mint", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: mint")
            message = f"Error {er}: mint"
            self._on_fail("mint", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, mint: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, mint. Reason: Unknown")

            self._on_fail("mint", message)

    def send_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).transact(tx_params.as_dict())

    def build_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).estimateGas(tx_params.as_dict())


class MintersMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the minters method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("minters")

    def validate_and_normalize_inputs(self, index_0: str) -> any:
        """Validate the inputs to the minters method."""
        self.validator.assert_valid(
            method_name='minters',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        return (index_0)

    def block_call(self, index_0: str, debug: bool = False) -> bool:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, index_0: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())


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


class RemoveMinterMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the removeMinter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeMinter")

    def validate_and_normalize_inputs(self, minter: str) -> any:
        """Validate the inputs to the removeMinter method."""
        self.validator.assert_valid(
            method_name='removeMinter',
            parameter_name='_minter',
            argument_value=minter,
        )
        minter = self.validate_and_checksum_address(minter)
        return (minter)

    def block_send(self, minter: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(minter)
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

                self._on_receipt_handle("remove_minter", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_minter")
            message = f"Error {er}: remove_minter"
            self._on_fail("remove_minter", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_minter: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_minter. Reason: Unknown")

            self._on_fail("remove_minter", message)

    def send_transaction(self, minter: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).transact(tx_params.as_dict())

    def build_transaction(self, minter: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, minter: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (minter) = self.validate_and_normalize_inputs(minter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(minter).estimateGas(tx_params.as_dict())


class SetGovernanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setGovernance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setGovernance")

    def validate_and_normalize_inputs(self, governance: str) -> any:
        """Validate the inputs to the setGovernance method."""
        self.validator.assert_valid(
            method_name='setGovernance',
            parameter_name='_governance',
            argument_value=governance,
        )
        governance = self.validate_and_checksum_address(governance)
        return (governance)

    def block_send(self, governance: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(governance)
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

                self._on_receipt_handle("set_governance", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_governance")
            message = f"Error {er}: set_governance"
            self._on_fail("set_governance", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_governance: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_governance. Reason: Unknown")

            self._on_fail("set_governance", message)

    def send_transaction(self, governance: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (governance) = self.validate_and_normalize_inputs(governance)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(governance).transact(tx_params.as_dict())

    def build_transaction(self, governance: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (governance) = self.validate_and_normalize_inputs(governance)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(governance).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, governance: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (governance) = self.validate_and_normalize_inputs(governance)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(governance).estimateGas(tx_params.as_dict())


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

    def validate_and_normalize_inputs(self, recipient: str, amount: int) -> any:
        """Validate the inputs to the transfer method."""
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='recipient',
            argument_value=recipient,
        )
        recipient = self.validate_and_checksum_address(recipient)
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (recipient, amount)

    def block_send(self, recipient: str, amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(recipient, amount)
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

    def send_transaction(self, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (recipient, amount) = self.validate_and_normalize_inputs(recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(recipient, amount).transact(tx_params.as_dict())

    def build_transaction(self, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (recipient, amount) = self.validate_and_normalize_inputs(recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(recipient, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (recipient, amount) = self.validate_and_normalize_inputs(recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(recipient, amount).estimateGas(tx_params.as_dict())


class TransferFromMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transferFrom method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("transferFrom")

    def validate_and_normalize_inputs(self, sender: str, recipient: str, amount: int) -> any:
        """Validate the inputs to the transferFrom method."""
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='sender',
            argument_value=sender,
        )
        sender = self.validate_and_checksum_address(sender)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='recipient',
            argument_value=recipient,
        )
        recipient = self.validate_and_checksum_address(recipient)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (sender, recipient, amount)

    def block_send(self, sender: str, recipient: str, amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(sender, recipient, amount)
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

    def send_transaction(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).transact(tx_params.as_dict())

    def build_transaction(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def add_minter(self) -> str:
        return self._function_signatures["addMinter"]

    def allowance(self) -> str:
        return self._function_signatures["allowance"]

    def approve(self) -> str:
        return self._function_signatures["approve"]

    def balance_of(self) -> str:
        return self._function_signatures["balanceOf"]

    def decimals(self) -> str:
        return self._function_signatures["decimals"]

    def decrease_allowance(self) -> str:
        return self._function_signatures["decreaseAllowance"]

    def governance(self) -> str:
        return self._function_signatures["governance"]

    def increase_allowance(self) -> str:
        return self._function_signatures["increaseAllowance"]

    def mint(self) -> str:
        return self._function_signatures["mint"]

    def minters(self) -> str:
        return self._function_signatures["minters"]

    def name(self) -> str:
        return self._function_signatures["name"]

    def remove_minter(self) -> str:
        return self._function_signatures["removeMinter"]

    def set_governance(self) -> str:
        return self._function_signatures["setGovernance"]

    def symbol(self) -> str:
        return self._function_signatures["symbol"]

    def total_supply(self) -> str:
        return self._function_signatures["totalSupply"]

    def transfer(self) -> str:
        return self._function_signatures["transfer"]

    def transfer_from(self) -> str:
        return self._function_signatures["transferFrom"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Tc20(ContractBase):
    """Wrapper class for Tc20 Solidity contract."""
    _fn_add_minter: AddMinterMethod
    """Constructor-initialized instance of
    :class:`AddMinterMethod`.
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

    _fn_decimals: DecimalsMethod
    """Constructor-initialized instance of
    :class:`DecimalsMethod`.
    """

    _fn_decrease_allowance: DecreaseAllowanceMethod
    """Constructor-initialized instance of
    :class:`DecreaseAllowanceMethod`.
    """

    _fn_governance: GovernanceMethod
    """Constructor-initialized instance of
    :class:`GovernanceMethod`.
    """

    _fn_increase_allowance: IncreaseAllowanceMethod
    """Constructor-initialized instance of
    :class:`IncreaseAllowanceMethod`.
    """

    _fn_mint: MintMethod
    """Constructor-initialized instance of
    :class:`MintMethod`.
    """

    _fn_minters: MintersMethod
    """Constructor-initialized instance of
    :class:`MintersMethod`.
    """

    _fn_name: NameMethod
    """Constructor-initialized instance of
    :class:`NameMethod`.
    """

    _fn_remove_minter: RemoveMinterMethod
    """Constructor-initialized instance of
    :class:`RemoveMinterMethod`.
    """

    _fn_set_governance: SetGovernanceMethod
    """Constructor-initialized instance of
    :class:`SetGovernanceMethod`.
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
            validator: Tc20Validator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, Tc20.abi())
        web3 = core_lib.w3

        if not validator:
            validator = Tc20Validator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Tc20.abi()).functions
        self._signatures = SignatureGenerator(Tc20.abi())
        validator.bindSignatures(self._signatures)

        self._fn_add_minter = AddMinterMethod(core_lib, contract_address, functions.addMinter, validator)
        self._fn_allowance = AllowanceMethod(core_lib, contract_address, functions.allowance, validator)
        self._fn_approve = ApproveMethod(core_lib, contract_address, functions.approve, validator)
        self._fn_balance_of = BalanceOfMethod(core_lib, contract_address, functions.balanceOf, validator)
        self._fn_decimals = DecimalsMethod(core_lib, contract_address, functions.decimals, validator)
        self._fn_decrease_allowance = DecreaseAllowanceMethod(core_lib, contract_address, functions.decreaseAllowance, validator)
        self._fn_governance = GovernanceMethod(core_lib, contract_address, functions.governance, validator)
        self._fn_increase_allowance = IncreaseAllowanceMethod(core_lib, contract_address, functions.increaseAllowance, validator)
        self._fn_mint = MintMethod(core_lib, contract_address, functions.mint, validator)
        self._fn_minters = MintersMethod(core_lib, contract_address, functions.minters, validator)
        self._fn_name = NameMethod(core_lib, contract_address, functions.name, validator)
        self._fn_remove_minter = RemoveMinterMethod(core_lib, contract_address, functions.removeMinter, validator)
        self._fn_set_governance = SetGovernanceMethod(core_lib, contract_address, functions.setGovernance, validator)
        self._fn_symbol = SymbolMethod(core_lib, contract_address, functions.symbol, validator)
        self._fn_total_supply = TotalSupplyMethod(core_lib, contract_address, functions.totalSupply, validator)
        self._fn_transfer = TransferMethod(core_lib, contract_address, functions.transfer, validator)
        self._fn_transfer_from = TransferFromMethod(core_lib, contract_address, functions.transferFrom, validator)

    def event_approval(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event approval in contract Tc20
        Get log entry for Approval event.
                :param tx_hash: hash of transaction emitting Approval event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Tc20.abi()).events.Approval().processReceipt(tx_receipt)

    def event_transfer(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event transfer in contract Tc20
        Get log entry for Transfer event.
                :param tx_hash: hash of transaction emitting Transfer event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Tc20.abi()).events.Transfer().processReceipt(tx_receipt)

    def add_minter(self, minter: str) -> None:
        """
        Implementation of add_minter in contract Tc20
        Method of the function

        """

        self._fn_add_minter.callback_onfail = self._callback_onfail
        self._fn_add_minter.callback_onsuccess = self._callback_onsuccess
        self._fn_add_minter.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_add_minter.gas_limit = self.call_contract_fee_amount
        self._fn_add_minter.gas_price_wei = self.call_contract_fee_price
        self._fn_add_minter.debug_method = self.call_contract_debug_flag

        return self._fn_add_minter.block_send(minter)

    def allowance(self, owner: str, spender: str) -> int:
        """
        Implementation of allowance in contract Tc20
        Method of the function

        """

        self._fn_allowance.callback_onfail = self._callback_onfail
        self._fn_allowance.callback_onsuccess = self._callback_onsuccess
        self._fn_allowance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_allowance.gas_limit = self.call_contract_fee_amount
        self._fn_allowance.gas_price_wei = self.call_contract_fee_price
        self._fn_allowance.debug_method = self.call_contract_debug_flag

        return self._fn_allowance.block_call(owner, spender)

    def approve(self, spender: str, amount: int) -> bool:
        """
        Implementation of approve in contract Tc20
        Method of the function

        """

        self._fn_approve.callback_onfail = self._callback_onfail
        self._fn_approve.callback_onsuccess = self._callback_onsuccess
        self._fn_approve.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_approve.gas_limit = self.call_contract_fee_amount
        self._fn_approve.gas_price_wei = self.call_contract_fee_price
        self._fn_approve.debug_method = self.call_contract_debug_flag

        return self._fn_approve.block_send(spender, amount)

    def balance_of(self, account: str) -> int:
        """
        Implementation of balance_of in contract Tc20
        Method of the function

        """

        self._fn_balance_of.callback_onfail = self._callback_onfail
        self._fn_balance_of.callback_onsuccess = self._callback_onsuccess
        self._fn_balance_of.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_balance_of.gas_limit = self.call_contract_fee_amount
        self._fn_balance_of.gas_price_wei = self.call_contract_fee_price
        self._fn_balance_of.debug_method = self.call_contract_debug_flag

        return self._fn_balance_of.block_call(account)

    def decimals(self) -> int:
        """
        Implementation of decimals in contract Tc20
        Method of the function

        """

        self._fn_decimals.callback_onfail = self._callback_onfail
        self._fn_decimals.callback_onsuccess = self._callback_onsuccess
        self._fn_decimals.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_decimals.gas_limit = self.call_contract_fee_amount
        self._fn_decimals.gas_price_wei = self.call_contract_fee_price
        self._fn_decimals.debug_method = self.call_contract_debug_flag

        return self._fn_decimals.block_call()

    def decrease_allowance(self, spender: str, subtracted_value: int) -> bool:
        """
        Implementation of decrease_allowance in contract Tc20
        Method of the function

        """

        self._fn_decrease_allowance.callback_onfail = self._callback_onfail
        self._fn_decrease_allowance.callback_onsuccess = self._callback_onsuccess
        self._fn_decrease_allowance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_decrease_allowance.gas_limit = self.call_contract_fee_amount
        self._fn_decrease_allowance.gas_price_wei = self.call_contract_fee_price
        self._fn_decrease_allowance.debug_method = self.call_contract_debug_flag

        return self._fn_decrease_allowance.block_send(spender, subtracted_value)

    def governance(self) -> str:
        """
        Implementation of governance in contract Tc20
        Method of the function

        """

        self._fn_governance.callback_onfail = self._callback_onfail
        self._fn_governance.callback_onsuccess = self._callback_onsuccess
        self._fn_governance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_governance.gas_limit = self.call_contract_fee_amount
        self._fn_governance.gas_price_wei = self.call_contract_fee_price
        self._fn_governance.debug_method = self.call_contract_debug_flag

        return self._fn_governance.block_call()

    def increase_allowance(self, spender: str, added_value: int) -> bool:
        """
        Implementation of increase_allowance in contract Tc20
        Method of the function

        """

        self._fn_increase_allowance.callback_onfail = self._callback_onfail
        self._fn_increase_allowance.callback_onsuccess = self._callback_onsuccess
        self._fn_increase_allowance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_increase_allowance.gas_limit = self.call_contract_fee_amount
        self._fn_increase_allowance.gas_price_wei = self.call_contract_fee_price
        self._fn_increase_allowance.debug_method = self.call_contract_debug_flag

        return self._fn_increase_allowance.block_send(spender, added_value)

    def mint(self, account: str, amount: int) -> None:
        """
        Implementation of mint in contract Tc20
        Method of the function

        """

        self._fn_mint.callback_onfail = self._callback_onfail
        self._fn_mint.callback_onsuccess = self._callback_onsuccess
        self._fn_mint.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_mint.gas_limit = self.call_contract_fee_amount
        self._fn_mint.gas_price_wei = self.call_contract_fee_price
        self._fn_mint.debug_method = self.call_contract_debug_flag

        return self._fn_mint.block_send(account, amount)

    def minters(self, index_0: str) -> bool:
        """
        Implementation of minters in contract Tc20
        Method of the function

        """

        self._fn_minters.callback_onfail = self._callback_onfail
        self._fn_minters.callback_onsuccess = self._callback_onsuccess
        self._fn_minters.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_minters.gas_limit = self.call_contract_fee_amount
        self._fn_minters.gas_price_wei = self.call_contract_fee_price
        self._fn_minters.debug_method = self.call_contract_debug_flag

        return self._fn_minters.block_call(index_0)

    def name(self) -> str:
        """
        Implementation of name in contract Tc20
        Method of the function

        """

        self._fn_name.callback_onfail = self._callback_onfail
        self._fn_name.callback_onsuccess = self._callback_onsuccess
        self._fn_name.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_name.gas_limit = self.call_contract_fee_amount
        self._fn_name.gas_price_wei = self.call_contract_fee_price
        self._fn_name.debug_method = self.call_contract_debug_flag

        return self._fn_name.block_call()

    def remove_minter(self, minter: str) -> None:
        """
        Implementation of remove_minter in contract Tc20
        Method of the function

        """

        self._fn_remove_minter.callback_onfail = self._callback_onfail
        self._fn_remove_minter.callback_onsuccess = self._callback_onsuccess
        self._fn_remove_minter.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_remove_minter.gas_limit = self.call_contract_fee_amount
        self._fn_remove_minter.gas_price_wei = self.call_contract_fee_price
        self._fn_remove_minter.debug_method = self.call_contract_debug_flag

        return self._fn_remove_minter.block_send(minter)

    def set_governance(self, governance: str) -> None:
        """
        Implementation of set_governance in contract Tc20
        Method of the function

        """

        self._fn_set_governance.callback_onfail = self._callback_onfail
        self._fn_set_governance.callback_onsuccess = self._callback_onsuccess
        self._fn_set_governance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_set_governance.gas_limit = self.call_contract_fee_amount
        self._fn_set_governance.gas_price_wei = self.call_contract_fee_price
        self._fn_set_governance.debug_method = self.call_contract_debug_flag

        return self._fn_set_governance.block_send(governance)

    def symbol(self) -> str:
        """
        Implementation of symbol in contract Tc20
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
        Implementation of total_supply in contract Tc20
        Method of the function

        """

        self._fn_total_supply.callback_onfail = self._callback_onfail
        self._fn_total_supply.callback_onsuccess = self._callback_onsuccess
        self._fn_total_supply.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_total_supply.gas_limit = self.call_contract_fee_amount
        self._fn_total_supply.gas_price_wei = self.call_contract_fee_price
        self._fn_total_supply.debug_method = self.call_contract_debug_flag

        return self._fn_total_supply.block_call()

    def transfer(self, recipient: str, amount: int) -> bool:
        """
        Implementation of transfer in contract Tc20
        Method of the function

        """

        self._fn_transfer.callback_onfail = self._callback_onfail
        self._fn_transfer.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer.gas_limit = self.call_contract_fee_amount
        self._fn_transfer.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer.debug_method = self.call_contract_debug_flag

        return self._fn_transfer.block_send(recipient, amount)

    def transfer_from(self, sender: str, recipient: str, amount: int) -> bool:
        """
        Implementation of transfer_from in contract Tc20
        Method of the function

        """

        self._fn_transfer_from.callback_onfail = self._callback_onfail
        self._fn_transfer_from.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer_from.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer_from.gas_limit = self.call_contract_fee_amount
        self._fn_transfer_from.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer_from.debug_method = self.call_contract_debug_flag

        return self._fn_transfer_from.block_send(sender, recipient, amount)

    def CallContractWait(self, t_long: int) -> "Tc20":
        self._fn_add_minter.setWait(t_long)
        self._fn_allowance.setWait(t_long)
        self._fn_approve.setWait(t_long)
        self._fn_balance_of.setWait(t_long)
        self._fn_decimals.setWait(t_long)
        self._fn_decrease_allowance.setWait(t_long)
        self._fn_governance.setWait(t_long)
        self._fn_increase_allowance.setWait(t_long)
        self._fn_mint.setWait(t_long)
        self._fn_minters.setWait(t_long)
        self._fn_name.setWait(t_long)
        self._fn_remove_minter.setWait(t_long)
        self._fn_set_governance.setWait(t_long)
        self._fn_symbol.setWait(t_long)
        self._fn_total_supply.setWait(t_long)
        self._fn_transfer.setWait(t_long)
        self._fn_transfer_from.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":false,"inputs":[{"internalType":"address","name":"_minter","type":"address"}],"name":"addMinter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"governance","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"index_0","type":"address"}],"name":"minters","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_minter","type":"address"}],"name":"removeMinter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_governance","type":"address"}],"name":"setGovernance","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
