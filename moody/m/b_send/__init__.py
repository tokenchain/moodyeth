"""Generated wrapper for BSend Solidity contract."""

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
# constructor for BSend below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        BSendValidator,
    )
except ImportError:

    class BSendValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AddSignerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addSigner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addSigner")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the addSigner method."""
        self.validator.assert_valid(
            method_name='addSigner',
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

                self._on_receipt_handle("add_signer", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_signer")
            message = f"Error {er}: add_signer"
            self._on_fail("add_signer", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_signer: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_signer. Reason: Unknown")

            self._on_fail("add_signer", message)

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


class BulkSendTrxMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the bulkSendTrx method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("bulkSendTrx")

    def validate_and_normalize_inputs(self, addresses: List[str], amounts: List[int]) -> any:
        """Validate the inputs to the bulkSendTrx method."""
        self.validator.assert_valid(
            method_name='bulkSendTrx',
            parameter_name='addresses',
            argument_value=addresses,
        )
        self.validator.assert_valid(
            method_name='bulkSendTrx',
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

                self._on_receipt_handle("bulk_send_trx", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: bulk_send_trx")
            message = f"Error {er}: bulk_send_trx"
            self._on_fail("bulk_send_trx", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_trx: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, bulk_send_trx. Reason: Unknown")

            self._on_fail("bulk_send_trx", message)

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


class ClaimInitMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the claimInit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("claimInit")

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

                self._on_receipt_handle("claim_init", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: claim_init")
            message = f"Error {er}: claim_init"
            self._on_fail("claim_init", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, claim_init: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, claim_init. Reason: Unknown")

            self._on_fail("claim_init", message)

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

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


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

    def estimate_gas(self, addr: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addr) = self.validate_and_normalize_inputs(addr)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr).estimateGas(tx_params.as_dict())


class IsSignerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isSigner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isSigner")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the isSigner method."""
        self.validator.assert_valid(
            method_name='isSigner',
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

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class RenounceSignerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the renounceSigner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("renounceSigner")

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

                self._on_receipt_handle("renounce_signer", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: renounce_signer")
            message = f"Error {er}: renounce_signer"
            self._on_fail("renounce_signer", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_signer: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, renounce_signer. Reason: Unknown")

            self._on_fail("renounce_signer", message)

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

    def add_signer(self) -> str:
        return self._function_signatures["addSigner"]

    def bulk_send_token(self) -> str:
        return self._function_signatures["bulkSendToken"]

    def bulk_send_trx(self) -> str:
        return self._function_signatures["bulkSendTrx"]

    def claim_init(self) -> str:
        return self._function_signatures["claimInit"]

    def deposit(self) -> str:
        return self._function_signatures["deposit"]

    def eth_send_fee(self) -> str:
        return self._function_signatures["ethSendFee"]

    def get_balance(self) -> str:
        return self._function_signatures["getBalance"]

    def is_signer(self) -> str:
        return self._function_signatures["isSigner"]

    def renounce_signer(self) -> str:
        return self._function_signatures["renounceSigner"]

    def set_eth_fee(self) -> str:
        return self._function_signatures["setEthFee"]

    def set_token_fee(self) -> str:
        return self._function_signatures["setTokenFee"]

    def token_send_fee(self) -> str:
        return self._function_signatures["tokenSendFee"]

    def withdraw_ether(self) -> str:
        return self._function_signatures["withdrawEther"]

    def withdraw_token(self) -> str:
        return self._function_signatures["withdrawToken"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class BSend(ContractBase):
    """Wrapper class for BSend Solidity contract."""
    _fn_add_signer: AddSignerMethod
    """Constructor-initialized instance of
    :class:`AddSignerMethod`.
    """

    _fn_bulk_send_token: BulkSendTokenMethod
    """Constructor-initialized instance of
    :class:`BulkSendTokenMethod`.
    """

    _fn_bulk_send_trx: BulkSendTrxMethod
    """Constructor-initialized instance of
    :class:`BulkSendTrxMethod`.
    """

    _fn_claim_init: ClaimInitMethod
    """Constructor-initialized instance of
    :class:`ClaimInitMethod`.
    """

    _fn_deposit: DepositMethod
    """Constructor-initialized instance of
    :class:`DepositMethod`.
    """

    _fn_eth_send_fee: EthSendFeeMethod
    """Constructor-initialized instance of
    :class:`EthSendFeeMethod`.
    """

    _fn_get_balance: GetBalanceMethod
    """Constructor-initialized instance of
    :class:`GetBalanceMethod`.
    """

    _fn_is_signer: IsSignerMethod
    """Constructor-initialized instance of
    :class:`IsSignerMethod`.
    """

    _fn_renounce_signer: RenounceSignerMethod
    """Constructor-initialized instance of
    :class:`RenounceSignerMethod`.
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
            validator: BSendValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, BSend.abi())
        web3 = core_lib.w3

        if not validator:
            validator = BSendValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=BSend.abi()).functions
        self._signatures = SignatureGenerator(BSend.abi())
        validator.bindSignatures(self._signatures)

        self._fn_add_signer = AddSignerMethod(core_lib, contract_address, functions.addSigner, validator)
        self._fn_bulk_send_token = BulkSendTokenMethod(core_lib, contract_address, functions.bulkSendToken, validator)
        self._fn_bulk_send_trx = BulkSendTrxMethod(core_lib, contract_address, functions.bulkSendTrx, validator)
        self._fn_claim_init = ClaimInitMethod(core_lib, contract_address, functions.claimInit, validator)
        self._fn_deposit = DepositMethod(core_lib, contract_address, functions.deposit, validator)
        self._fn_eth_send_fee = EthSendFeeMethod(core_lib, contract_address, functions.ethSendFee, validator)
        self._fn_get_balance = GetBalanceMethod(core_lib, contract_address, functions.getBalance, validator)
        self._fn_is_signer = IsSignerMethod(core_lib, contract_address, functions.isSigner, validator)
        self._fn_renounce_signer = RenounceSignerMethod(core_lib, contract_address, functions.renounceSigner, validator)
        self._fn_set_eth_fee = SetEthFeeMethod(core_lib, contract_address, functions.setEthFee, validator)
        self._fn_set_token_fee = SetTokenFeeMethod(core_lib, contract_address, functions.setTokenFee, validator)
        self._fn_token_send_fee = TokenSendFeeMethod(core_lib, contract_address, functions.tokenSendFee, validator)
        self._fn_withdraw_ether = WithdrawEtherMethod(core_lib, contract_address, functions.withdrawEther, validator)
        self._fn_withdraw_token = WithdrawTokenMethod(core_lib, contract_address, functions.withdrawToken, validator)

    def event_signer_added(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event signer_added in contract BSend
        Get log entry for SignerAdded event.
                :param tx_hash: hash of transaction emitting SignerAdded event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend.abi()).events.SignerAdded().processReceipt(tx_receipt)

    def event_signer_removed(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event signer_removed in contract BSend
        Get log entry for SignerRemoved event.
                :param tx_hash: hash of transaction emitting SignerRemoved event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend.abi()).events.SignerRemoved().processReceipt(tx_receipt)

    def add_signer(self, account: str) -> None:
        """
        Implementation of add_signer in contract BSend
        Method of the function

        """

        self._fn_add_signer.callback_onfail = self._callback_onfail
        self._fn_add_signer.callback_onsuccess = self._callback_onsuccess
        self._fn_add_signer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_add_signer.gas_limit = self.call_contract_fee_amount
        self._fn_add_signer.gas_price_wei = self.call_contract_fee_price
        self._fn_add_signer.debug_method = self.call_contract_debug_flag

        return self._fn_add_signer.block_send(account)

    def bulk_send_token(self, token_addr: str, addresses: List[str], amounts: List[int], wei: int = 0) -> bool:
        """
        Implementation of bulk_send_token in contract BSend
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

    def bulk_send_trx(self, addresses: List[str], amounts: List[int], wei: int = 0) -> bool:
        """
        Implementation of bulk_send_trx in contract BSend
        Method of the function

        """

        self._fn_bulk_send_trx.callback_onfail = self._callback_onfail
        self._fn_bulk_send_trx.callback_onsuccess = self._callback_onsuccess
        self._fn_bulk_send_trx.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_bulk_send_trx.gas_limit = self.call_contract_fee_amount
        self._fn_bulk_send_trx.gas_price_wei = self.call_contract_fee_price
        self._fn_bulk_send_trx.debug_method = self.call_contract_debug_flag

        self._fn_bulk_send_trx.wei_value = wei

        return self._fn_bulk_send_trx.block_send(addresses, amounts, wei)

    def claim_init(self) -> None:
        """
        Implementation of claim_init in contract BSend
        Method of the function

        """

        self._fn_claim_init.callback_onfail = self._callback_onfail
        self._fn_claim_init.callback_onsuccess = self._callback_onsuccess
        self._fn_claim_init.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_claim_init.gas_limit = self.call_contract_fee_amount
        self._fn_claim_init.gas_price_wei = self.call_contract_fee_price
        self._fn_claim_init.debug_method = self.call_contract_debug_flag

        return self._fn_claim_init.block_send()

    def deposit(self, wei: int = 0) -> bool:
        """
        Implementation of deposit in contract BSend
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
        Implementation of eth_send_fee in contract BSend
        Method of the function

        """

        self._fn_eth_send_fee.callback_onfail = self._callback_onfail
        self._fn_eth_send_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_eth_send_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_eth_send_fee.gas_limit = self.call_contract_fee_amount
        self._fn_eth_send_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_eth_send_fee.debug_method = self.call_contract_debug_flag

        return self._fn_eth_send_fee.block_call()

    def get_balance(self, addr: str) -> int:
        """
        Implementation of get_balance in contract BSend
        Method of the function

        """

        self._fn_get_balance.callback_onfail = self._callback_onfail
        self._fn_get_balance.callback_onsuccess = self._callback_onsuccess
        self._fn_get_balance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_balance.gas_limit = self.call_contract_fee_amount
        self._fn_get_balance.gas_price_wei = self.call_contract_fee_price
        self._fn_get_balance.debug_method = self.call_contract_debug_flag

        return self._fn_get_balance.block_call(addr)

    def is_signer(self, account: str) -> bool:
        """
        Implementation of is_signer in contract BSend
        Method of the function

        """

        self._fn_is_signer.callback_onfail = self._callback_onfail
        self._fn_is_signer.callback_onsuccess = self._callback_onsuccess
        self._fn_is_signer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_is_signer.gas_limit = self.call_contract_fee_amount
        self._fn_is_signer.gas_price_wei = self.call_contract_fee_price
        self._fn_is_signer.debug_method = self.call_contract_debug_flag

        return self._fn_is_signer.block_call(account)

    def renounce_signer(self) -> None:
        """
        Implementation of renounce_signer in contract BSend
        Method of the function

        """

        self._fn_renounce_signer.callback_onfail = self._callback_onfail
        self._fn_renounce_signer.callback_onsuccess = self._callback_onsuccess
        self._fn_renounce_signer.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_renounce_signer.gas_limit = self.call_contract_fee_amount
        self._fn_renounce_signer.gas_price_wei = self.call_contract_fee_price
        self._fn_renounce_signer.debug_method = self.call_contract_debug_flag

        return self._fn_renounce_signer.block_send()

    def set_eth_fee(self, eth_send_fee: int) -> bool:
        """
        Implementation of set_eth_fee in contract BSend
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
        Implementation of set_token_fee in contract BSend
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
        Implementation of token_send_fee in contract BSend
        Method of the function

        """

        self._fn_token_send_fee.callback_onfail = self._callback_onfail
        self._fn_token_send_fee.callback_onsuccess = self._callback_onsuccess
        self._fn_token_send_fee.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_token_send_fee.gas_limit = self.call_contract_fee_amount
        self._fn_token_send_fee.gas_price_wei = self.call_contract_fee_price
        self._fn_token_send_fee.debug_method = self.call_contract_debug_flag

        return self._fn_token_send_fee.block_call()

    def withdraw_ether(self, addr: str, amount: int) -> bool:
        """
        Implementation of withdraw_ether in contract BSend
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
        Implementation of withdraw_token in contract BSend
        Method of the function

        """

        self._fn_withdraw_token.callback_onfail = self._callback_onfail
        self._fn_withdraw_token.callback_onsuccess = self._callback_onsuccess
        self._fn_withdraw_token.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_withdraw_token.gas_limit = self.call_contract_fee_amount
        self._fn_withdraw_token.gas_price_wei = self.call_contract_fee_price
        self._fn_withdraw_token.debug_method = self.call_contract_debug_flag

        return self._fn_withdraw_token.block_send(token_addr, to, amount)

    def CallContractWait(self, t_long: int) -> "BSend":
        self._fn_add_signer.setWait(t_long)
        self._fn_bulk_send_token.setWait(t_long)
        self._fn_bulk_send_trx.setWait(t_long)
        self._fn_claim_init.setWait(t_long)
        self._fn_deposit.setWait(t_long)
        self._fn_eth_send_fee.setWait(t_long)
        self._fn_get_balance.setWait(t_long)
        self._fn_is_signer.setWait(t_long)
        self._fn_renounce_signer.setWait(t_long)
        self._fn_set_eth_fee.setWait(t_long)
        self._fn_set_token_fee.setWait(t_long)
        self._fn_token_send_fee.setWait(t_long)
        self._fn_withdraw_ether.setWait(t_long)
        self._fn_withdraw_token.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"payable":true,"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"}],"name":"SignerAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"}],"name":"SignerRemoved","type":"event"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"addSigner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendTrx","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[],"name":"claimInit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[],"name":"ethSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"getBalance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isSigner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"renounceSigner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_ethSendFee","type":"uint256"}],"name":"setEthFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_tokenSendFee","type":"uint256"}],"name":"setTokenFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"tokenSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"addr","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdrawEther","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdrawToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
