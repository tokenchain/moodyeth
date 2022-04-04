"""Generated wrapper for BSend2 Solidity contract."""

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
# constructor for BSend2 below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        BSend2Validator,
    )
except ImportError:

    class BSend2Validator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class DefaultAdminRoleMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the DEFAULT_ADMIN_ROLE method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("DEFAULT_ADMIN_ROLE")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def block_send(self, _valeth: int = 0) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("default_admin_role", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: default_admin_role")
            message = f"Error {er}: default_admin_role"
            self._on_fail("default_admin_role", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, default_admin_role: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, default_admin_role. Reason: Unknown")

            self._on_fail("default_admin_role", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class AddGovernorMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addGovernor method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addGovernor")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the addGovernor method."""
        self.validator.assert_valid(
            method_name='addGovernor',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_send(self, account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("add_governor", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_governor")
            message = f"Error {er}: add_governor"
            self._on_fail("add_governor", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_governor: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_governor. Reason: Unknown")

            self._on_fail("add_governor", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class AddWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addWhitelistAdmin")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the addWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='addWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_send(self, account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("add_whitelist_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_whitelist_admin")
            message = f"Error {er}: add_whitelist_admin"
            self._on_fail("add_whitelist_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_whitelist_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_whitelist_admin. Reason: Unknown")

            self._on_fail("add_whitelist_admin", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class BulkSendNativeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the bulkSendNative method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("bulkSendNative")

    def validate_and_normalize_inputs(self, addresses: List[str], amounts: List[int]) -> any:
        """Validate the inputs to the bulkSendNative method."""
        self.validator.assert_valid(
            method_name='bulkSendNative',
            parameter_name='addresses',
            argument_value=addresses,
        )
        self.validator.assert_valid(
            method_name='bulkSendNative',
            parameter_name='amounts',
            argument_value=amounts,
        )
        return (addresses, amounts)

    def block_send(self, addresses: List[str], amounts: List[int], _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(addresses, amounts)
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

                self._on_receipt_handle("bulk_send_native", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: bulk_send_native")
            message = f"Error {er}: bulk_send_native"
            self._on_fail("bulk_send_native", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_native: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_native. Reason: Unknown")

            self._on_fail("bulk_send_native", message)

    def send_transaction(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).transact(tx_params.as_dict())

    def build_transaction(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).estimateGas(tx_params.as_dict())


class BulkSendTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the bulkSendToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("bulkSendToken")

    def validate_and_normalize_inputs(self, token_addr: str, addresses: List[str], amounts: List[int]) -> any:
        """Validate the inputs to the bulkSendToken method."""
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='tokenAddr',
            argument_value=token_addr,
        )
        token_addr = self.validate_and_checksum_address(token_addr)
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='addresses',
            argument_value=addresses,
        )
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='amounts',
            argument_value=amounts,
        )
        return (token_addr, addresses, amounts)

    def block_send(self, token_addr: str, addresses: List[str], amounts: List[int], _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_addr, addresses, amounts)
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

                self._on_receipt_handle("bulk_send_token", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: bulk_send_token")
            message = f"Error {er}: bulk_send_token"
            self._on_fail("bulk_send_token", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_token: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_token. Reason: Unknown")

            self._on_fail("bulk_send_token", message)

    def send_transaction(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).transact(tx_params.as_dict())

    def build_transaction(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).estimateGas(tx_params.as_dict())


class DepositMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the deposit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("deposit")

    def block_send(self, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("deposit", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: deposit")
            message = f"Error {er}: deposit"
            self._on_fail("deposit", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, deposit: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, deposit. Reason: Unknown")

            self._on_fail("deposit", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class EthSendFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the ethSendFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("ethSendFee")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, _valeth: int = 0) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("eth_send_fee", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: eth_send_fee")
            message = f"Error {er}: eth_send_fee"
            self._on_fail("eth_send_fee", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, eth_send_fee: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, eth_send_fee. Reason: Unknown")

            self._on_fail("eth_send_fee", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class ExpressTransferMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the expressTransfer method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("expressTransfer")

    def validate_and_normalize_inputs(self, data: List[Union[bytes, str]]) -> any:
        """Validate the inputs to the expressTransfer method."""
        self.validator.assert_valid(
            method_name='expressTransfer',
            parameter_name='_data',
            argument_value=data,
        )
        return (data)

    def block_send(self, data: List[Union[bytes, str]], _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(data)
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

                self._on_receipt_handle("express_transfer", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: express_transfer")
            message = f"Error {er}: express_transfer"
            self._on_fail("express_transfer", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, express_transfer: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, express_transfer. Reason: Unknown")

            self._on_fail("express_transfer", message)

    def send_transaction(self, data: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (data) = self.validate_and_normalize_inputs(data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(data).transact(tx_params.as_dict())

    def build_transaction(self, data: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (data) = self.validate_and_normalize_inputs(data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, data: List[Union[bytes, str]], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (data) = self.validate_and_normalize_inputs(data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(data).estimateGas(tx_params.as_dict())


class GetBalanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getBalance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getBalance")

    def validate_and_normalize_inputs(self, addr: str) -> any:
        """Validate the inputs to the getBalance method."""
        self.validator.assert_valid(
            method_name='getBalance',
            parameter_name='addr',
            argument_value=addr,
        )
        addr = self.validate_and_checksum_address(addr)
        return (addr)

    def block_call(self, addr: str, debug: bool = False) -> int:
        _fn = self._underlying_method(addr)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, addr: str, _valeth: int = 0) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(addr)
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

                self._on_receipt_handle("get_balance", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_balance")
            message = f"Error {er}: get_balance"
            self._on_fail("get_balance", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_balance: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_balance. Reason: Unknown")

            self._on_fail("get_balance", message)

    def send_transaction(self, addr: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (addr) = self.validate_and_normalize_inputs(addr)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr).transact(tx_params.as_dict())

    def build_transaction(self, addr: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (addr) = self.validate_and_normalize_inputs(addr)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, addr: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addr) = self.validate_and_normalize_inputs(addr)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr).estimateGas(tx_params.as_dict())


class GetRoleAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getRoleAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getRoleAdmin")

    def validate_and_normalize_inputs(self, role: Union[bytes, str]) -> any:
        """Validate the inputs to the getRoleAdmin method."""
        self.validator.assert_valid(
            method_name='getRoleAdmin',
            parameter_name='role',
            argument_value=role,
        )
        return (role)

    def block_call(self, role: Union[bytes, str], debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method(role)
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def block_send(self, role: Union[bytes, str], _valeth: int = 0) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role)
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

                self._on_receipt_handle("get_role_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_role_admin")
            message = f"Error {er}: get_role_admin"
            self._on_fail("get_role_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_admin. Reason: Unknown")

            self._on_fail("get_role_admin", message)

    def send_transaction(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).estimateGas(tx_params.as_dict())


class GetRoleMemberMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getRoleMember method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getRoleMember")

    def validate_and_normalize_inputs(self, role: Union[bytes, str], index: int) -> any:
        """Validate the inputs to the getRoleMember method."""
        self.validator.assert_valid(
            method_name='getRoleMember',
            parameter_name='role',
            argument_value=role,
        )
        self.validator.assert_valid(
            method_name='getRoleMember',
            parameter_name='index',
            argument_value=index,
        )
        # safeguard against fractional inputs
        index = int(index)
        return (role, index)

    def block_call(self, role: Union[bytes, str], index: int, debug: bool = False) -> str:
        _fn = self._underlying_method(role, index)
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def block_send(self, role: Union[bytes, str], index: int, _valeth: int = 0) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role, index)
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

                self._on_receipt_handle("get_role_member", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_role_member")
            message = f"Error {er}: get_role_member"
            self._on_fail("get_role_member", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_member: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_member. Reason: Unknown")

            self._on_fail("get_role_member", message)

    def send_transaction(self, role: Union[bytes, str], index: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role, index) = self.validate_and_normalize_inputs(role, index)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, index).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], index: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role, index) = self.validate_and_normalize_inputs(role, index)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, index).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], index: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role, index) = self.validate_and_normalize_inputs(role, index)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, index).estimateGas(tx_params.as_dict())


class GetRoleMemberCountMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getRoleMemberCount method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getRoleMemberCount")

    def validate_and_normalize_inputs(self, role: Union[bytes, str]) -> any:
        """Validate the inputs to the getRoleMemberCount method."""
        self.validator.assert_valid(
            method_name='getRoleMemberCount',
            parameter_name='role',
            argument_value=role,
        )
        return (role)

    def block_call(self, role: Union[bytes, str], debug: bool = False) -> int:
        _fn = self._underlying_method(role)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, role: Union[bytes, str], _valeth: int = 0) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role)
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

                self._on_receipt_handle("get_role_member_count", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_role_member_count")
            message = f"Error {er}: get_role_member_count"
            self._on_fail("get_role_member_count", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_member_count: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_role_member_count. Reason: Unknown")

            self._on_fail("get_role_member_count", message)

    def send_transaction(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role) = self.validate_and_normalize_inputs(role)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role).estimateGas(tx_params.as_dict())


class GovernorMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the governor method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("governor")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def block_send(self, _valeth: int = 0) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("governor", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: governor")
            message = f"Error {er}: governor"
            self._on_fail("governor", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, governor: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, governor. Reason: Unknown")

            self._on_fail("governor", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class GrantRoleMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the grantRole method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("grantRole")

    def validate_and_normalize_inputs(self, role: Union[bytes, str], account: str) -> any:
        """Validate the inputs to the grantRole method."""
        self.validator.assert_valid(
            method_name='grantRole',
            parameter_name='role',
            argument_value=role,
        )
        self.validator.assert_valid(
            method_name='grantRole',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (role, account)

    def block_send(self, role: Union[bytes, str], account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role, account)
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

                self._on_receipt_handle("grant_role", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: grant_role")
            message = f"Error {er}: grant_role"
            self._on_fail("grant_role", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, grant_role: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, grant_role. Reason: Unknown")

            self._on_fail("grant_role", message)

    def send_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).estimateGas(tx_params.as_dict())


class HasRoleMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the hasRole method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("hasRole")

    def validate_and_normalize_inputs(self, role: Union[bytes, str], account: str) -> any:
        """Validate the inputs to the hasRole method."""
        self.validator.assert_valid(
            method_name='hasRole',
            parameter_name='role',
            argument_value=role,
        )
        self.validator.assert_valid(
            method_name='hasRole',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (role, account)

    def block_call(self, role: Union[bytes, str], account: str, debug: bool = False) -> bool:
        _fn = self._underlying_method(role, account)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, role: Union[bytes, str], account: str, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role, account)
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

                self._on_receipt_handle("has_role", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: has_role")
            message = f"Error {er}: has_role"
            self._on_fail("has_role", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, has_role: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, has_role. Reason: Unknown")

            self._on_fail("has_role", message)

    def send_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).estimateGas(tx_params.as_dict())


class IsGovernorMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isGovernor method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isGovernor")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the isGovernor method."""
        self.validator.assert_valid(
            method_name='isGovernor',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, debug: bool = False) -> bool:
        _fn = self._underlying_method(account)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, account: str, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("is_governor", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_governor")
            message = f"Error {er}: is_governor"
            self._on_fail("is_governor", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_governor: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_governor. Reason: Unknown")

            self._on_fail("is_governor", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class IsLockedMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isLocked method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isLocked")

    def block_call(self, debug: bool = False) -> bool:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("is_locked", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_locked")
            message = f"Error {er}: is_locked"
            self._on_fail("is_locked", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_locked: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_locked. Reason: Unknown")

            self._on_fail("is_locked", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class IsOwnerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isOwner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isOwner")

    def block_call(self, debug: bool = False) -> bool:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("is_owner", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_owner")
            message = f"Error {er}: is_owner"
            self._on_fail("is_owner", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_owner: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_owner. Reason: Unknown")

            self._on_fail("is_owner", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class IsPausedMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isPaused method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isPaused")

    def block_call(self, debug: bool = False) -> bool:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("is_paused", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_paused")
            message = f"Error {er}: is_paused"
            self._on_fail("is_paused", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_paused: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_paused. Reason: Unknown")

            self._on_fail("is_paused", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class IsWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isWhitelistAdmin")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the isWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='isWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, debug: bool = False) -> bool:
        _fn = self._underlying_method(account)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, account: str, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("is_whitelist_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_whitelist_admin")
            message = f"Error {er}: is_whitelist_admin"
            self._on_fail("is_whitelist_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_whitelist_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_whitelist_admin. Reason: Unknown")

            self._on_fail("is_whitelist_admin", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class LockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the lock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("lock")

    def block_send(self, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("lock", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: lock")
            message = f"Error {er}: lock"
            self._on_fail("lock", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, lock: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, lock. Reason: Unknown")

            self._on_fail("lock", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class OwnerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the owner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("owner")

    def block_call(self, debug: bool = False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def block_send(self, _valeth: int = 0) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("owner", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: owner")
            message = f"Error {er}: owner"
            self._on_fail("owner", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, owner: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, owner. Reason: Unknown")

            self._on_fail("owner", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class PauseScMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the pauseSc method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("pauseSc")

    def block_send(self, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("pause_sc", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: pause_sc")
            message = f"Error {er}: pause_sc"
            self._on_fail("pause_sc", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, pause_sc: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, pause_sc. Reason: Unknown")

            self._on_fail("pause_sc", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class RemoveGovernorMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the removeGovernor method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeGovernor")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the removeGovernor method."""
        self.validator.assert_valid(
            method_name='removeGovernor',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_send(self, account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("remove_governor", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_governor")
            message = f"Error {er}: remove_governor"
            self._on_fail("remove_governor", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_governor: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_governor. Reason: Unknown")

            self._on_fail("remove_governor", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class RemoveWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the removeWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeWhitelistAdmin")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the removeWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='removeWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_send(self, account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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

                self._on_receipt_handle("remove_whitelist_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_whitelist_admin")
            message = f"Error {er}: remove_whitelist_admin"
            self._on_fail("remove_whitelist_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_whitelist_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_whitelist_admin. Reason: Unknown")

            self._on_fail("remove_whitelist_admin", message)

    def send_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).transact(tx_params.as_dict())

    def build_transaction(self, account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class RenounceOwnershipMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the renounceOwnership method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("renounceOwnership")

    def block_send(self, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("renounce_ownership", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: renounce_ownership")
            message = f"Error {er}: renounce_ownership"
            self._on_fail("renounce_ownership", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_ownership: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_ownership. Reason: Unknown")

            self._on_fail("renounce_ownership", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class RenounceRoleMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the renounceRole method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("renounceRole")

    def validate_and_normalize_inputs(self, role: Union[bytes, str], account: str) -> any:
        """Validate the inputs to the renounceRole method."""
        self.validator.assert_valid(
            method_name='renounceRole',
            parameter_name='role',
            argument_value=role,
        )
        self.validator.assert_valid(
            method_name='renounceRole',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (role, account)

    def block_send(self, role: Union[bytes, str], account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role, account)
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

                self._on_receipt_handle("renounce_role", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: renounce_role")
            message = f"Error {er}: renounce_role"
            self._on_fail("renounce_role", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_role: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_role. Reason: Unknown")

            self._on_fail("renounce_role", message)

    def send_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).estimateGas(tx_params.as_dict())


class RevokeRoleMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the revokeRole method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("revokeRole")

    def validate_and_normalize_inputs(self, role: Union[bytes, str], account: str) -> any:
        """Validate the inputs to the revokeRole method."""
        self.validator.assert_valid(
            method_name='revokeRole',
            parameter_name='role',
            argument_value=role,
        )
        self.validator.assert_valid(
            method_name='revokeRole',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (role, account)

    def block_send(self, role: Union[bytes, str], account: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(role, account)
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

                self._on_receipt_handle("revoke_role", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: revoke_role")
            message = f"Error {er}: revoke_role"
            self._on_fail("revoke_role", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, revoke_role: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, revoke_role. Reason: Unknown")

            self._on_fail("revoke_role", message)

    def send_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).transact(tx_params.as_dict())

    def build_transaction(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, role: Union[bytes, str], account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (role, account) = self.validate_and_normalize_inputs(role, account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(role, account).estimateGas(tx_params.as_dict())


class SetEthFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setEthFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setEthFee")

    def validate_and_normalize_inputs(self, eth_send_fee: int) -> any:
        """Validate the inputs to the setEthFee method."""
        self.validator.assert_valid(
            method_name='setEthFee',
            parameter_name='_ethSendFee',
            argument_value=eth_send_fee,
        )
        # safeguard against fractional inputs
        eth_send_fee = int(eth_send_fee)
        return (eth_send_fee)

    def block_send(self, eth_send_fee: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(eth_send_fee)
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

                self._on_receipt_handle("set_eth_fee", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_eth_fee")
            message = f"Error {er}: set_eth_fee"
            self._on_fail("set_eth_fee", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_eth_fee: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_eth_fee. Reason: Unknown")

            self._on_fail("set_eth_fee", message)

    def send_transaction(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).transact(tx_params.as_dict())

    def build_transaction(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).estimateGas(tx_params.as_dict())


class SetTokenFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setTokenFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setTokenFee")

    def validate_and_normalize_inputs(self, token_send_fee: int) -> any:
        """Validate the inputs to the setTokenFee method."""
        self.validator.assert_valid(
            method_name='setTokenFee',
            parameter_name='_tokenSendFee',
            argument_value=token_send_fee,
        )
        # safeguard against fractional inputs
        token_send_fee = int(token_send_fee)
        return (token_send_fee)

    def block_send(self, token_send_fee: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_send_fee)
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

                self._on_receipt_handle("set_token_fee", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_token_fee")
            message = f"Error {er}: set_token_fee"
            self._on_fail("set_token_fee", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_token_fee: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_token_fee. Reason: Unknown")

            self._on_fail("set_token_fee", message)

    def send_transaction(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).transact(tx_params.as_dict())

    def build_transaction(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).estimateGas(tx_params.as_dict())


class TokenSendFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tokenSendFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("tokenSendFee")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, _valeth: int = 0) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("token_send_fee", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: token_send_fee")
            message = f"Error {er}: token_send_fee"
            self._on_fail("token_send_fee", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, token_send_fee: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, token_send_fee. Reason: Unknown")

            self._on_fail("token_send_fee", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class TransferOwnershipMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transferOwnership method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("transferOwnership")

    def validate_and_normalize_inputs(self, new_owner: str) -> any:
        """Validate the inputs to the transferOwnership method."""
        self.validator.assert_valid(
            method_name='transferOwnership',
            parameter_name='newOwner',
            argument_value=new_owner,
        )
        new_owner = self.validate_and_checksum_address(new_owner)
        return (new_owner)

    def block_send(self, new_owner: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_owner)
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

                self._on_receipt_handle("transfer_ownership", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer_ownership")
            message = f"Error {er}: transfer_ownership"
            self._on_fail("transfer_ownership", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_ownership: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_ownership. Reason: Unknown")

            self._on_fail("transfer_ownership", message)

    def send_transaction(self, new_owner: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_owner) = self.validate_and_normalize_inputs(new_owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_owner).transact(tx_params.as_dict())

    def build_transaction(self, new_owner: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_owner) = self.validate_and_normalize_inputs(new_owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_owner).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_owner: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_owner) = self.validate_and_normalize_inputs(new_owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_owner).estimateGas(tx_params.as_dict())


class UnlockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the unlock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("unlock")

    def block_send(self, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("unlock", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: unlock")
            message = f"Error {er}: unlock"
            self._on_fail("unlock", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, unlock: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, unlock. Reason: Unknown")

            self._on_fail("unlock", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class UnpauseScMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the unpauseSc method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("unpauseSc")

    def block_send(self, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("unpause_sc", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: unpause_sc")
            message = f"Error {er}: unpause_sc"
            self._on_fail("unpause_sc", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, unpause_sc: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, unpause_sc. Reason: Unknown")

            self._on_fail("unpause_sc", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class WhitelistAdminsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the whitelistAdmins method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("whitelistAdmins")

    def block_call(self, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def block_send(self, _valeth: int = 0) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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

                self._on_receipt_handle("whitelist_admins", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: whitelist_admins")
            message = f"Error {er}: whitelist_admins"
            self._on_fail("whitelist_admins", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, whitelist_admins: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, whitelist_admins. Reason: Unknown")

            self._on_fail("whitelist_admins", message)

    def send_transaction(self, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().transact(tx_params.as_dict())

    def build_transaction(self, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().buildTransaction(tx_params.as_dict())

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class WithdrawEtherMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdrawEther method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("withdrawEther")

    def validate_and_normalize_inputs(self, addr: str, amount: int) -> any:
        """Validate the inputs to the withdrawEther method."""
        self.validator.assert_valid(
            method_name='withdrawEther',
            parameter_name='addr',
            argument_value=addr,
        )
        addr = self.validate_and_checksum_address(addr)
        self.validator.assert_valid(
            method_name='withdrawEther',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (addr, amount)

    def block_send(self, addr: str, amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(addr, amount)
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

                self._on_receipt_handle("withdraw_ether", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: withdraw_ether")
            message = f"Error {er}: withdraw_ether"
            self._on_fail("withdraw_ether", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw_ether: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw_ether. Reason: Unknown")

            self._on_fail("withdraw_ether", message)

    def send_transaction(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).transact(tx_params.as_dict())

    def build_transaction(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).estimateGas(tx_params.as_dict())


class WithdrawTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdrawToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("withdrawToken")

    def validate_and_normalize_inputs(self, token_addr: str, to: str, amount: int) -> any:
        """Validate the inputs to the withdrawToken method."""
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='tokenAddr',
            argument_value=token_addr,
        )
        token_addr = self.validate_and_checksum_address(token_addr)
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='_to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='_amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (token_addr, to, amount)

    def block_send(self, token_addr: str, to: str, amount: int, _valeth: int = 0) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_addr, to, amount)
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

                self._on_receipt_handle("withdraw_token", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: withdraw_token")
            message = f"Error {er}: withdraw_token"
            self._on_fail("withdraw_token", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw_token: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw_token. Reason: Unknown")

            self._on_fail("withdraw_token", message)

    def send_transaction(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).transact(tx_params.as_dict())

    def build_transaction(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def default_admin_role(self) -> str:
        return self._function_signatures["DEFAULT_ADMIN_ROLE"]

    def add_governor(self) -> str:
        return self._function_signatures["addGovernor"]

    def add_whitelist_admin(self) -> str:
        return self._function_signatures["addWhitelistAdmin"]

    def bulk_send_native(self) -> str:
        return self._function_signatures["bulkSendNative"]

    def bulk_send_token(self) -> str:
        return self._function_signatures["bulkSendToken"]

    def deposit(self) -> str:
        return self._function_signatures["deposit"]

    def eth_send_fee(self) -> str:
        return self._function_signatures["ethSendFee"]

    def express_transfer(self) -> str:
        return self._function_signatures["expressTransfer"]

    def get_balance(self) -> str:
        return self._function_signatures["getBalance"]

    def get_role_admin(self) -> str:
        return self._function_signatures["getRoleAdmin"]

    def get_role_member(self) -> str:
        return self._function_signatures["getRoleMember"]

    def get_role_member_count(self) -> str:
        return self._function_signatures["getRoleMemberCount"]

    def governor(self) -> str:
        return self._function_signatures["governor"]

    def grant_role(self) -> str:
        return self._function_signatures["grantRole"]

    def has_role(self) -> str:
        return self._function_signatures["hasRole"]

    def is_governor(self) -> str:
        return self._function_signatures["isGovernor"]

    def is_locked(self) -> str:
        return self._function_signatures["isLocked"]

    def is_owner(self) -> str:
        return self._function_signatures["isOwner"]

    def is_paused(self) -> str:
        return self._function_signatures["isPaused"]

    def is_whitelist_admin(self) -> str:
        return self._function_signatures["isWhitelistAdmin"]

    def lock(self) -> str:
        return self._function_signatures["lock"]

    def owner(self) -> str:
        return self._function_signatures["owner"]

    def pause_sc(self) -> str:
        return self._function_signatures["pauseSc"]

    def remove_governor(self) -> str:
        return self._function_signatures["removeGovernor"]

    def remove_whitelist_admin(self) -> str:
        return self._function_signatures["removeWhitelistAdmin"]

    def renounce_ownership(self) -> str:
        return self._function_signatures["renounceOwnership"]

    def renounce_role(self) -> str:
        return self._function_signatures["renounceRole"]

    def revoke_role(self) -> str:
        return self._function_signatures["revokeRole"]

    def set_eth_fee(self) -> str:
        return self._function_signatures["setEthFee"]

    def set_token_fee(self) -> str:
        return self._function_signatures["setTokenFee"]

    def token_send_fee(self) -> str:
        return self._function_signatures["tokenSendFee"]

    def transfer_ownership(self) -> str:
        return self._function_signatures["transferOwnership"]

    def unlock(self) -> str:
        return self._function_signatures["unlock"]

    def unpause_sc(self) -> str:
        return self._function_signatures["unpauseSc"]

    def whitelist_admins(self) -> str:
        return self._function_signatures["whitelistAdmins"]

    def withdraw_ether(self) -> str:
        return self._function_signatures["withdrawEther"]

    def withdraw_token(self) -> str:
        return self._function_signatures["withdrawToken"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class BSend2(ContractBase):
    """Wrapper class for BSend2 Solidity contract."""
    _fn_default_admin_role: DefaultAdminRoleMethod
    """Constructor-initialized instance of
    :class:`DefaultAdminRoleMethod`.
    """

    _fn_add_governor: AddGovernorMethod
    """Constructor-initialized instance of
    :class:`AddGovernorMethod`.
    """

    _fn_add_whitelist_admin: AddWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`AddWhitelistAdminMethod`.
    """

    _fn_bulk_send_native: BulkSendNativeMethod
    """Constructor-initialized instance of
    :class:`BulkSendNativeMethod`.
    """

    _fn_bulk_send_token: BulkSendTokenMethod
    """Constructor-initialized instance of
    :class:`BulkSendTokenMethod`.
    """

    _fn_deposit: DepositMethod
    """Constructor-initialized instance of
    :class:`DepositMethod`.
    """

    _fn_eth_send_fee: EthSendFeeMethod
    """Constructor-initialized instance of
    :class:`EthSendFeeMethod`.
    """

    _fn_express_transfer: ExpressTransferMethod
    """Constructor-initialized instance of
    :class:`ExpressTransferMethod`.
    """

    _fn_get_balance: GetBalanceMethod
    """Constructor-initialized instance of
    :class:`GetBalanceMethod`.
    """

    _fn_get_role_admin: GetRoleAdminMethod
    """Constructor-initialized instance of
    :class:`GetRoleAdminMethod`.
    """

    _fn_get_role_member: GetRoleMemberMethod
    """Constructor-initialized instance of
    :class:`GetRoleMemberMethod`.
    """

    _fn_get_role_member_count: GetRoleMemberCountMethod
    """Constructor-initialized instance of
    :class:`GetRoleMemberCountMethod`.
    """

    _fn_governor: GovernorMethod
    """Constructor-initialized instance of
    :class:`GovernorMethod`.
    """

    _fn_grant_role: GrantRoleMethod
    """Constructor-initialized instance of
    :class:`GrantRoleMethod`.
    """

    _fn_has_role: HasRoleMethod
    """Constructor-initialized instance of
    :class:`HasRoleMethod`.
    """

    _fn_is_governor: IsGovernorMethod
    """Constructor-initialized instance of
    :class:`IsGovernorMethod`.
    """

    _fn_is_locked: IsLockedMethod
    """Constructor-initialized instance of
    :class:`IsLockedMethod`.
    """

    _fn_is_owner: IsOwnerMethod
    """Constructor-initialized instance of
    :class:`IsOwnerMethod`.
    """

    _fn_is_paused: IsPausedMethod
    """Constructor-initialized instance of
    :class:`IsPausedMethod`.
    """

    _fn_is_whitelist_admin: IsWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`IsWhitelistAdminMethod`.
    """

    _fn_lock: LockMethod
    """Constructor-initialized instance of
    :class:`LockMethod`.
    """

    _fn_owner: OwnerMethod
    """Constructor-initialized instance of
    :class:`OwnerMethod`.
    """

    _fn_pause_sc: PauseScMethod
    """Constructor-initialized instance of
    :class:`PauseScMethod`.
    """

    _fn_remove_governor: RemoveGovernorMethod
    """Constructor-initialized instance of
    :class:`RemoveGovernorMethod`.
    """

    _fn_remove_whitelist_admin: RemoveWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`RemoveWhitelistAdminMethod`.
    """

    _fn_renounce_ownership: RenounceOwnershipMethod
    """Constructor-initialized instance of
    :class:`RenounceOwnershipMethod`.
    """

    _fn_renounce_role: RenounceRoleMethod
    """Constructor-initialized instance of
    :class:`RenounceRoleMethod`.
    """

    _fn_revoke_role: RevokeRoleMethod
    """Constructor-initialized instance of
    :class:`RevokeRoleMethod`.
    """

    _fn_set_eth_fee: SetEthFeeMethod
    """Constructor-initialized instance of
    :class:`SetEthFeeMethod`.
    """

    _fn_set_token_fee: SetTokenFeeMethod
    """Constructor-initialized instance of
    :class:`SetTokenFeeMethod`.
    """

    _fn_token_send_fee: TokenSendFeeMethod
    """Constructor-initialized instance of
    :class:`TokenSendFeeMethod`.
    """

    _fn_transfer_ownership: TransferOwnershipMethod
    """Constructor-initialized instance of
    :class:`TransferOwnershipMethod`.
    """

    _fn_unlock: UnlockMethod
    """Constructor-initialized instance of
    :class:`UnlockMethod`.
    """

    _fn_unpause_sc: UnpauseScMethod
    """Constructor-initialized instance of
    :class:`UnpauseScMethod`.
    """

    _fn_whitelist_admins: WhitelistAdminsMethod
    """Constructor-initialized instance of
    :class:`WhitelistAdminsMethod`.
    """

    _fn_withdraw_ether: WithdrawEtherMethod
    """Constructor-initialized instance of
    :class:`WithdrawEtherMethod`.
    """

    _fn_withdraw_token: WithdrawTokenMethod
    """Constructor-initialized instance of
    :class:`WithdrawTokenMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: BSend2Validator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, BSend2.abi())
        web3 = core_lib.w3

        if not validator:
            validator = BSend2Validator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=BSend2.abi()).functions
        self._signatures = SignatureGenerator(BSend2.abi())
        validator.bindSignatures(self._signatures)

        self._fn_default_admin_role = DefaultAdminRoleMethod(core_lib, contract_address, functions.DEFAULT_ADMIN_ROLE, validator)
        self._fn_add_governor = AddGovernorMethod(core_lib, contract_address, functions.addGovernor, validator)
        self._fn_add_whitelist_admin = AddWhitelistAdminMethod(core_lib, contract_address, functions.addWhitelistAdmin, validator)
        self._fn_bulk_send_native = BulkSendNativeMethod(core_lib, contract_address, functions.bulkSendNative, validator)
        self._fn_bulk_send_token = BulkSendTokenMethod(core_lib, contract_address, functions.bulkSendToken, validator)
        self._fn_deposit = DepositMethod(core_lib, contract_address, functions.deposit, validator)
        self._fn_eth_send_fee = EthSendFeeMethod(core_lib, contract_address, functions.ethSendFee, validator)
        self._fn_express_transfer = ExpressTransferMethod(core_lib, contract_address, functions.expressTransfer, validator)
        self._fn_get_balance = GetBalanceMethod(core_lib, contract_address, functions.getBalance, validator)
        self._fn_get_role_admin = GetRoleAdminMethod(core_lib, contract_address, functions.getRoleAdmin, validator)
        self._fn_get_role_member = GetRoleMemberMethod(core_lib, contract_address, functions.getRoleMember, validator)
        self._fn_get_role_member_count = GetRoleMemberCountMethod(core_lib, contract_address, functions.getRoleMemberCount, validator)
        self._fn_governor = GovernorMethod(core_lib, contract_address, functions.governor, validator)
        self._fn_grant_role = GrantRoleMethod(core_lib, contract_address, functions.grantRole, validator)
        self._fn_has_role = HasRoleMethod(core_lib, contract_address, functions.hasRole, validator)
        self._fn_is_governor = IsGovernorMethod(core_lib, contract_address, functions.isGovernor, validator)
        self._fn_is_locked = IsLockedMethod(core_lib, contract_address, functions.isLocked, validator)
        self._fn_is_owner = IsOwnerMethod(core_lib, contract_address, functions.isOwner, validator)
        self._fn_is_paused = IsPausedMethod(core_lib, contract_address, functions.isPaused, validator)
        self._fn_is_whitelist_admin = IsWhitelistAdminMethod(core_lib, contract_address, functions.isWhitelistAdmin, validator)
        self._fn_lock = LockMethod(core_lib, contract_address, functions.lock, validator)
        self._fn_owner = OwnerMethod(core_lib, contract_address, functions.owner, validator)
        self._fn_pause_sc = PauseScMethod(core_lib, contract_address, functions.pauseSc, validator)
        self._fn_remove_governor = RemoveGovernorMethod(core_lib, contract_address, functions.removeGovernor, validator)
        self._fn_remove_whitelist_admin = RemoveWhitelistAdminMethod(core_lib, contract_address, functions.removeWhitelistAdmin, validator)
        self._fn_renounce_ownership = RenounceOwnershipMethod(core_lib, contract_address, functions.renounceOwnership, validator)
        self._fn_renounce_role = RenounceRoleMethod(core_lib, contract_address, functions.renounceRole, validator)
        self._fn_revoke_role = RevokeRoleMethod(core_lib, contract_address, functions.revokeRole, validator)
        self._fn_set_eth_fee = SetEthFeeMethod(core_lib, contract_address, functions.setEthFee, validator)
        self._fn_set_token_fee = SetTokenFeeMethod(core_lib, contract_address, functions.setTokenFee, validator)
        self._fn_token_send_fee = TokenSendFeeMethod(core_lib, contract_address, functions.tokenSendFee, validator)
        self._fn_transfer_ownership = TransferOwnershipMethod(core_lib, contract_address, functions.transferOwnership, validator)
        self._fn_unlock = UnlockMethod(core_lib, contract_address, functions.unlock, validator)
        self._fn_unpause_sc = UnpauseScMethod(core_lib, contract_address, functions.unpauseSc, validator)
        self._fn_whitelist_admins = WhitelistAdminsMethod(core_lib, contract_address, functions.whitelistAdmins, validator)
        self._fn_withdraw_ether = WithdrawEtherMethod(core_lib, contract_address, functions.withdrawEther, validator)
        self._fn_withdraw_token = WithdrawTokenMethod(core_lib, contract_address, functions.withdrawToken, validator)

    def event_ownership_transferred(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event ownership_transferred in contract BSend2
        Get log entry for OwnershipTransferred event.
                :param tx_hash: hash of transaction emitting OwnershipTransferred event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend2.abi()).events.OwnershipTransferred().processReceipt(tx_receipt)

    def event_role_granted(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event role_granted in contract BSend2
        Get log entry for RoleGranted event.
                :param tx_hash: hash of transaction emitting RoleGranted event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend2.abi()).events.RoleGranted().processReceipt(tx_receipt)

    def event_role_revoked(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event role_revoked in contract BSend2
        Get log entry for RoleRevoked event.
                :param tx_hash: hash of transaction emitting RoleRevoked event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend2.abi()).events.RoleRevoked().processReceipt(tx_receipt)

    def event_contract_paused(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event contract_paused in contract BSend2
        Get log entry for contractPaused event.
                :param tx_hash: hash of transaction emitting contractPaused event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend2.abi()).events.contractPaused().processReceipt(tx_receipt)

    def event_traillock(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event traillock in contract BSend2
        Get log entry for traillock event.
                :param tx_hash: hash of transaction emitting traillock event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend2.abi()).events.traillock().processReceipt(tx_receipt)

    def default_admin_role(self) -> Union[bytes, str]:
        """
        Implementation of default_admin_role in contract BSend2
        Method of the function

        """

        self._fn_default_admin_role.callback_onfail = self._callback_onfail
        self._fn_default_admin_role.callback_onsuccess = self._callback_onsuccess
        self._fn_default_admin_role.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_default_admin_role.gas_limit = self.call_contract_fee_amount
        self._fn_default_admin_role.gas_price_wei = self.call_contract_fee_price
        self._fn_default_admin_role.debug_method = self.call_contract_debug_flag

        return self._fn_default_admin_role.block_call()

    def add_governor(self, account: str) -> None:
        """
        Implementation of add_governor in contract BSend2
        Method of the function

        """

        self._fn_add_governor.callback_onfail = self._callback_onfail
        self._fn_add_governor.callback_onsuccess = self._callback_onsuccess
        self._fn_add_governor.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_add_governor.gas_limit = self.call_contract_fee_amount
        self._fn_add_governor.gas_price_wei = self.call_contract_fee_price
        self._fn_add_governor.debug_method = self.call_contract_debug_flag

        return self._fn_add_governor.block_send(account)

    def add_whitelist_admin(self, account: str) -> None:
        """
        Implementation of add_whitelist_admin in contract BSend2
        Method of the function

        """

        self._fn_add_whitelist_admin.callback_onfail = self._callback_onfail
        self._fn_add_whitelist_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_add_whitelist_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_add_whitelist_admin.gas_limit = self.call_contract_fee_amount
        self._fn_add_whitelist_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_add_whitelist_admin.debug_method = self.call_contract_debug_flag

        return self._fn_add_whitelist_admin.block_send(account)

    def bulk_send_native(self, addresses: List[str], amounts: List[int], wei: int = 0) -> bool:
        """
        Implementation of bulk_send_native in contract BSend2
        Method of the function

        """

        self._fn_bulk_send_native.callback_onfail = self._callback_onfail
        self._fn_bulk_send_native.callback_onsuccess = self._callback_onsuccess
        self._fn_bulk_send_native.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_bulk_send_native.gas_limit = self.call_contract_fee_amount
        self._fn_bulk_send_native.gas_price_wei = self.call_contract_fee_price
        self._fn_bulk_send_native.debug_method = self.call_contract_debug_flag

        self._fn_bulk_send_native.wei_value = wei

        return self._fn_bulk_send_native.block_send(addresses, amounts, wei)

    def bulk_send_token(self, token_addr: str, addresses: List[str], amounts: List[int], wei: int = 0) -> bool:
        """
        Implementation of bulk_send_token in contract BSend2
        Method of the function

        """

        self._fn_bulk_send_token.callback_onfail = self._callback_onfail
        self._fn_bulk_send_token.callback_onsuccess = self._callback_onsuccess
        self._fn_bulk_send_token.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_bulk_send_token.gas_limit = self.call_contract_fee_amount
        self._fn_bulk_send_token.gas_price_wei = self.call_contract_fee_price
        self._fn_bulk_send_token.debug_method = self.call_contract_debug_flag

        self._fn_bulk_send_token.wei_value = wei

        return self._fn_bulk_send_token.block_send(token_addr, addresses, amounts, wei)

    def deposit(self, wei: int = 0) -> bool:
        """
        Implementation of deposit in contract BSend2
        Method of the function

        """

        self._fn_deposit.callback_onfail = self._callback_onfail
        self._fn_deposit.callback_onsuccess = self._callback_onsuccess
        self._fn_deposit.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_deposit.gas_limit = self.call_contract_fee_amount
        self._fn_deposit.gas_price_wei = self.call_contract_fee_price
        self._fn_deposit.debug_method = self.call_contract_debug_flag

        self._fn_deposit.wei_value = wei

        return self._fn_deposit.block_send(wei)

    def eth_send_fee(self) -> int:
        """
        Implementation of eth_send_fee in contract BSend2
        Method of the function

        """

        self._fn_eth_send_fee.callback_onfail = self._callback_onfail
        self._fn_eth_send_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_eth_send_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_eth_send_fee.gas_limit = self.call_contract_fee_amount
        self._fn_eth_send_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_eth_send_fee.debug_method = self.call_contract_debug_flag

        return self._fn_eth_send_fee.block_call()

    def express_transfer(self, data: List[Union[bytes, str]], wei: int = 0) -> None:
        """
        Implementation of express_transfer in contract BSend2
        Method of the function

        """

        self._fn_express_transfer.callback_onfail = self._callback_onfail
        self._fn_express_transfer.callback_onsuccess = self._callback_onsuccess
        self._fn_express_transfer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_express_transfer.gas_limit = self.call_contract_fee_amount
        self._fn_express_transfer.gas_price_wei = self.call_contract_fee_price
        self._fn_express_transfer.debug_method = self.call_contract_debug_flag

        self._fn_express_transfer.wei_value = wei

        return self._fn_express_transfer.block_send(data, wei)

    def get_balance(self, addr: str) -> int:
        """
        Implementation of get_balance in contract BSend2
        Method of the function

        """

        self._fn_get_balance.callback_onfail = self._callback_onfail
        self._fn_get_balance.callback_onsuccess = self._callback_onsuccess
        self._fn_get_balance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_balance.gas_limit = self.call_contract_fee_amount
        self._fn_get_balance.gas_price_wei = self.call_contract_fee_price
        self._fn_get_balance.debug_method = self.call_contract_debug_flag

        return self._fn_get_balance.block_call(addr)

    def get_role_admin(self, role: Union[bytes, str]) -> Union[bytes, str]:
        """
        Implementation of get_role_admin in contract BSend2
        Method of the function

        """

        self._fn_get_role_admin.callback_onfail = self._callback_onfail
        self._fn_get_role_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_get_role_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_role_admin.gas_limit = self.call_contract_fee_amount
        self._fn_get_role_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_get_role_admin.debug_method = self.call_contract_debug_flag

        return self._fn_get_role_admin.block_call(role)

    def get_role_member(self, role: Union[bytes, str], index: int) -> str:
        """
        Implementation of get_role_member in contract BSend2
        Method of the function

        """

        self._fn_get_role_member.callback_onfail = self._callback_onfail
        self._fn_get_role_member.callback_onsuccess = self._callback_onsuccess
        self._fn_get_role_member.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_role_member.gas_limit = self.call_contract_fee_amount
        self._fn_get_role_member.gas_price_wei = self.call_contract_fee_price
        self._fn_get_role_member.debug_method = self.call_contract_debug_flag

        return self._fn_get_role_member.block_call(role, index)

    def get_role_member_count(self, role: Union[bytes, str]) -> int:
        """
        Implementation of get_role_member_count in contract BSend2
        Method of the function

        """

        self._fn_get_role_member_count.callback_onfail = self._callback_onfail
        self._fn_get_role_member_count.callback_onsuccess = self._callback_onsuccess
        self._fn_get_role_member_count.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_role_member_count.gas_limit = self.call_contract_fee_amount
        self._fn_get_role_member_count.gas_price_wei = self.call_contract_fee_price
        self._fn_get_role_member_count.debug_method = self.call_contract_debug_flag

        return self._fn_get_role_member_count.block_call(role)

    def governor(self) -> Union[bytes, str]:
        """
        Implementation of governor in contract BSend2
        Method of the function

        """

        self._fn_governor.callback_onfail = self._callback_onfail
        self._fn_governor.callback_onsuccess = self._callback_onsuccess
        self._fn_governor.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_governor.gas_limit = self.call_contract_fee_amount
        self._fn_governor.gas_price_wei = self.call_contract_fee_price
        self._fn_governor.debug_method = self.call_contract_debug_flag

        return self._fn_governor.block_call()

    def grant_role(self, role: Union[bytes, str], account: str) -> None:
        """
        Implementation of grant_role in contract BSend2
        Method of the function

        """

        self._fn_grant_role.callback_onfail = self._callback_onfail
        self._fn_grant_role.callback_onsuccess = self._callback_onsuccess
        self._fn_grant_role.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_grant_role.gas_limit = self.call_contract_fee_amount
        self._fn_grant_role.gas_price_wei = self.call_contract_fee_price
        self._fn_grant_role.debug_method = self.call_contract_debug_flag

        return self._fn_grant_role.block_send(role, account)

    def has_role(self, role: Union[bytes, str], account: str) -> bool:
        """
        Implementation of has_role in contract BSend2
        Method of the function

        """

        self._fn_has_role.callback_onfail = self._callback_onfail
        self._fn_has_role.callback_onsuccess = self._callback_onsuccess
        self._fn_has_role.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_has_role.gas_limit = self.call_contract_fee_amount
        self._fn_has_role.gas_price_wei = self.call_contract_fee_price
        self._fn_has_role.debug_method = self.call_contract_debug_flag

        return self._fn_has_role.block_call(role, account)

    def is_governor(self, account: str) -> bool:
        """
        Implementation of is_governor in contract BSend2
        Method of the function

        """

        self._fn_is_governor.callback_onfail = self._callback_onfail
        self._fn_is_governor.callback_onsuccess = self._callback_onsuccess
        self._fn_is_governor.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_governor.gas_limit = self.call_contract_fee_amount
        self._fn_is_governor.gas_price_wei = self.call_contract_fee_price
        self._fn_is_governor.debug_method = self.call_contract_debug_flag

        return self._fn_is_governor.block_call(account)

    def is_locked(self) -> bool:
        """
        Implementation of is_locked in contract BSend2
        Method of the function

        """

        self._fn_is_locked.callback_onfail = self._callback_onfail
        self._fn_is_locked.callback_onsuccess = self._callback_onsuccess
        self._fn_is_locked.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_locked.gas_limit = self.call_contract_fee_amount
        self._fn_is_locked.gas_price_wei = self.call_contract_fee_price
        self._fn_is_locked.debug_method = self.call_contract_debug_flag

        return self._fn_is_locked.block_call()

    def is_owner(self) -> bool:
        """
        Implementation of is_owner in contract BSend2
        Method of the function

        """

        self._fn_is_owner.callback_onfail = self._callback_onfail
        self._fn_is_owner.callback_onsuccess = self._callback_onsuccess
        self._fn_is_owner.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_owner.gas_limit = self.call_contract_fee_amount
        self._fn_is_owner.gas_price_wei = self.call_contract_fee_price
        self._fn_is_owner.debug_method = self.call_contract_debug_flag

        return self._fn_is_owner.block_call()

    def is_paused(self) -> bool:
        """
        Implementation of is_paused in contract BSend2
        Method of the function

        """

        self._fn_is_paused.callback_onfail = self._callback_onfail
        self._fn_is_paused.callback_onsuccess = self._callback_onsuccess
        self._fn_is_paused.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_paused.gas_limit = self.call_contract_fee_amount
        self._fn_is_paused.gas_price_wei = self.call_contract_fee_price
        self._fn_is_paused.debug_method = self.call_contract_debug_flag

        return self._fn_is_paused.block_call()

    def is_whitelist_admin(self, account: str) -> bool:
        """
        Implementation of is_whitelist_admin in contract BSend2
        Method of the function

        """

        self._fn_is_whitelist_admin.callback_onfail = self._callback_onfail
        self._fn_is_whitelist_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_is_whitelist_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_whitelist_admin.gas_limit = self.call_contract_fee_amount
        self._fn_is_whitelist_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_is_whitelist_admin.debug_method = self.call_contract_debug_flag

        return self._fn_is_whitelist_admin.block_call(account)

    def lock(self) -> None:
        """
        Implementation of lock in contract BSend2
        Method of the function

        """

        self._fn_lock.callback_onfail = self._callback_onfail
        self._fn_lock.callback_onsuccess = self._callback_onsuccess
        self._fn_lock.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_lock.gas_limit = self.call_contract_fee_amount
        self._fn_lock.gas_price_wei = self.call_contract_fee_price
        self._fn_lock.debug_method = self.call_contract_debug_flag

        return self._fn_lock.block_send()

    def owner(self) -> str:
        """
        Implementation of owner in contract BSend2
        Method of the function

        """

        self._fn_owner.callback_onfail = self._callback_onfail
        self._fn_owner.callback_onsuccess = self._callback_onsuccess
        self._fn_owner.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_owner.gas_limit = self.call_contract_fee_amount
        self._fn_owner.gas_price_wei = self.call_contract_fee_price
        self._fn_owner.debug_method = self.call_contract_debug_flag

        return self._fn_owner.block_call()

    def pause_sc(self) -> None:
        """
        Implementation of pause_sc in contract BSend2
        Method of the function

        """

        self._fn_pause_sc.callback_onfail = self._callback_onfail
        self._fn_pause_sc.callback_onsuccess = self._callback_onsuccess
        self._fn_pause_sc.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_pause_sc.gas_limit = self.call_contract_fee_amount
        self._fn_pause_sc.gas_price_wei = self.call_contract_fee_price
        self._fn_pause_sc.debug_method = self.call_contract_debug_flag

        return self._fn_pause_sc.block_send()

    def remove_governor(self, account: str) -> None:
        """
        Implementation of remove_governor in contract BSend2
        Method of the function

        """

        self._fn_remove_governor.callback_onfail = self._callback_onfail
        self._fn_remove_governor.callback_onsuccess = self._callback_onsuccess
        self._fn_remove_governor.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_remove_governor.gas_limit = self.call_contract_fee_amount
        self._fn_remove_governor.gas_price_wei = self.call_contract_fee_price
        self._fn_remove_governor.debug_method = self.call_contract_debug_flag

        return self._fn_remove_governor.block_send(account)

    def remove_whitelist_admin(self, account: str) -> None:
        """
        Implementation of remove_whitelist_admin in contract BSend2
        Method of the function

        """

        self._fn_remove_whitelist_admin.callback_onfail = self._callback_onfail
        self._fn_remove_whitelist_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_remove_whitelist_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_remove_whitelist_admin.gas_limit = self.call_contract_fee_amount
        self._fn_remove_whitelist_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_remove_whitelist_admin.debug_method = self.call_contract_debug_flag

        return self._fn_remove_whitelist_admin.block_send(account)

    def renounce_ownership(self) -> None:
        """
        Implementation of renounce_ownership in contract BSend2
        Method of the function

        """

        self._fn_renounce_ownership.callback_onfail = self._callback_onfail
        self._fn_renounce_ownership.callback_onsuccess = self._callback_onsuccess
        self._fn_renounce_ownership.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_renounce_ownership.gas_limit = self.call_contract_fee_amount
        self._fn_renounce_ownership.gas_price_wei = self.call_contract_fee_price
        self._fn_renounce_ownership.debug_method = self.call_contract_debug_flag

        return self._fn_renounce_ownership.block_send()

    def renounce_role(self, role: Union[bytes, str], account: str) -> None:
        """
        Implementation of renounce_role in contract BSend2
        Method of the function

        """

        self._fn_renounce_role.callback_onfail = self._callback_onfail
        self._fn_renounce_role.callback_onsuccess = self._callback_onsuccess
        self._fn_renounce_role.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_renounce_role.gas_limit = self.call_contract_fee_amount
        self._fn_renounce_role.gas_price_wei = self.call_contract_fee_price
        self._fn_renounce_role.debug_method = self.call_contract_debug_flag

        return self._fn_renounce_role.block_send(role, account)

    def revoke_role(self, role: Union[bytes, str], account: str) -> None:
        """
        Implementation of revoke_role in contract BSend2
        Method of the function

        """

        self._fn_revoke_role.callback_onfail = self._callback_onfail
        self._fn_revoke_role.callback_onsuccess = self._callback_onsuccess
        self._fn_revoke_role.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_revoke_role.gas_limit = self.call_contract_fee_amount
        self._fn_revoke_role.gas_price_wei = self.call_contract_fee_price
        self._fn_revoke_role.debug_method = self.call_contract_debug_flag

        return self._fn_revoke_role.block_send(role, account)

    def set_eth_fee(self, eth_send_fee: int) -> bool:
        """
        Implementation of set_eth_fee in contract BSend2
        Method of the function

        """

        self._fn_set_eth_fee.callback_onfail = self._callback_onfail
        self._fn_set_eth_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_set_eth_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_set_eth_fee.gas_limit = self.call_contract_fee_amount
        self._fn_set_eth_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_set_eth_fee.debug_method = self.call_contract_debug_flag

        return self._fn_set_eth_fee.block_send(eth_send_fee)

    def set_token_fee(self, token_send_fee: int) -> bool:
        """
        Implementation of set_token_fee in contract BSend2
        Method of the function

        """

        self._fn_set_token_fee.callback_onfail = self._callback_onfail
        self._fn_set_token_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_set_token_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_set_token_fee.gas_limit = self.call_contract_fee_amount
        self._fn_set_token_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_set_token_fee.debug_method = self.call_contract_debug_flag

        return self._fn_set_token_fee.block_send(token_send_fee)

    def token_send_fee(self) -> int:
        """
        Implementation of token_send_fee in contract BSend2
        Method of the function

        """

        self._fn_token_send_fee.callback_onfail = self._callback_onfail
        self._fn_token_send_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_token_send_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_token_send_fee.gas_limit = self.call_contract_fee_amount
        self._fn_token_send_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_token_send_fee.debug_method = self.call_contract_debug_flag

        return self._fn_token_send_fee.block_call()

    def transfer_ownership(self, new_owner: str) -> None:
        """
        Implementation of transfer_ownership in contract BSend2
        Method of the function

        """

        self._fn_transfer_ownership.callback_onfail = self._callback_onfail
        self._fn_transfer_ownership.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer_ownership.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer_ownership.gas_limit = self.call_contract_fee_amount
        self._fn_transfer_ownership.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer_ownership.debug_method = self.call_contract_debug_flag

        return self._fn_transfer_ownership.block_send(new_owner)

    def unlock(self) -> None:
        """
        Implementation of unlock in contract BSend2
        Method of the function

        """

        self._fn_unlock.callback_onfail = self._callback_onfail
        self._fn_unlock.callback_onsuccess = self._callback_onsuccess
        self._fn_unlock.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_unlock.gas_limit = self.call_contract_fee_amount
        self._fn_unlock.gas_price_wei = self.call_contract_fee_price
        self._fn_unlock.debug_method = self.call_contract_debug_flag

        return self._fn_unlock.block_send()

    def unpause_sc(self) -> None:
        """
        Implementation of unpause_sc in contract BSend2
        Method of the function

        """

        self._fn_unpause_sc.callback_onfail = self._callback_onfail
        self._fn_unpause_sc.callback_onsuccess = self._callback_onsuccess
        self._fn_unpause_sc.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_unpause_sc.gas_limit = self.call_contract_fee_amount
        self._fn_unpause_sc.gas_price_wei = self.call_contract_fee_price
        self._fn_unpause_sc.debug_method = self.call_contract_debug_flag

        return self._fn_unpause_sc.block_send()

    def whitelist_admins(self) -> Union[bytes, str]:
        """
        Implementation of whitelist_admins in contract BSend2
        Method of the function

        """

        self._fn_whitelist_admins.callback_onfail = self._callback_onfail
        self._fn_whitelist_admins.callback_onsuccess = self._callback_onsuccess
        self._fn_whitelist_admins.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_whitelist_admins.gas_limit = self.call_contract_fee_amount
        self._fn_whitelist_admins.gas_price_wei = self.call_contract_fee_price
        self._fn_whitelist_admins.debug_method = self.call_contract_debug_flag

        return self._fn_whitelist_admins.block_call()

    def withdraw_ether(self, addr: str, amount: int) -> bool:
        """
        Implementation of withdraw_ether in contract BSend2
        Method of the function

        """

        self._fn_withdraw_ether.callback_onfail = self._callback_onfail
        self._fn_withdraw_ether.callback_onsuccess = self._callback_onsuccess
        self._fn_withdraw_ether.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_withdraw_ether.gas_limit = self.call_contract_fee_amount
        self._fn_withdraw_ether.gas_price_wei = self.call_contract_fee_price
        self._fn_withdraw_ether.debug_method = self.call_contract_debug_flag

        return self._fn_withdraw_ether.block_send(addr, amount)

    def withdraw_token(self, token_addr: str, to: str, amount: int) -> bool:
        """
        Implementation of withdraw_token in contract BSend2
        Method of the function

        """

        self._fn_withdraw_token.callback_onfail = self._callback_onfail
        self._fn_withdraw_token.callback_onsuccess = self._callback_onsuccess
        self._fn_withdraw_token.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_withdraw_token.gas_limit = self.call_contract_fee_amount
        self._fn_withdraw_token.gas_price_wei = self.call_contract_fee_price
        self._fn_withdraw_token.debug_method = self.call_contract_debug_flag

        return self._fn_withdraw_token.block_send(token_addr, to, amount)

    def CallContractWait(self, t_long: int) -> "BSend2":
        self._fn_default_admin_role.setWait(t_long)
        self._fn_add_governor.setWait(t_long)
        self._fn_add_whitelist_admin.setWait(t_long)
        self._fn_bulk_send_native.setWait(t_long)
        self._fn_bulk_send_token.setWait(t_long)
        self._fn_deposit.setWait(t_long)
        self._fn_eth_send_fee.setWait(t_long)
        self._fn_express_transfer.setWait(t_long)
        self._fn_get_balance.setWait(t_long)
        self._fn_get_role_admin.setWait(t_long)
        self._fn_get_role_member.setWait(t_long)
        self._fn_get_role_member_count.setWait(t_long)
        self._fn_governor.setWait(t_long)
        self._fn_grant_role.setWait(t_long)
        self._fn_has_role.setWait(t_long)
        self._fn_is_governor.setWait(t_long)
        self._fn_is_locked.setWait(t_long)
        self._fn_is_owner.setWait(t_long)
        self._fn_is_paused.setWait(t_long)
        self._fn_is_whitelist_admin.setWait(t_long)
        self._fn_lock.setWait(t_long)
        self._fn_owner.setWait(t_long)
        self._fn_pause_sc.setWait(t_long)
        self._fn_remove_governor.setWait(t_long)
        self._fn_remove_whitelist_admin.setWait(t_long)
        self._fn_renounce_ownership.setWait(t_long)
        self._fn_renounce_role.setWait(t_long)
        self._fn_revoke_role.setWait(t_long)
        self._fn_set_eth_fee.setWait(t_long)
        self._fn_set_token_fee.setWait(t_long)
        self._fn_token_send_fee.setWait(t_long)
        self._fn_transfer_ownership.setWait(t_long)
        self._fn_unlock.setWait(t_long)
        self._fn_unpause_sc.setWait(t_long)
        self._fn_whitelist_admins.setWait(t_long)
        self._fn_withdraw_ether.setWait(t_long)
        self._fn_withdraw_token.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"bool","name":"value","type":"bool"}],"name":"contractPaused","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint8","name":"value","type":"uint8"}],"name":"traillock","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"addGovernor","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"addWhitelistAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendNative","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"deposit","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"ethSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes[]","name":"_data","type":"bytes[]"}],"name":"expressTransfer","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"getBalance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"uint256","name":"index","type":"uint256"}],"name":"getRoleMember","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleMemberCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"governor","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isGovernor","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isLocked","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isPaused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isWhitelistAdmin","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lock","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pauseSc","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"removeGovernor","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"removeWhitelistAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_ethSendFee","type":"uint256"}],"name":"setEthFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_tokenSendFee","type":"uint256"}],"name":"setTokenFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"tokenSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"unlock","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"unpauseSc","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"whitelistAdmins","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"addr","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdrawEther","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdrawToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
