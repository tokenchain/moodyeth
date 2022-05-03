"""Generated wrapper for ProxyAdmin Solidity contract."""

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
# constructor for ProxyAdmin below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        ProxyAdminValidator,
    )
except ImportError:

    class ProxyAdminValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class ChangeProxyAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the changeProxyAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("changeProxyAdmin")

    def validate_and_normalize_inputs(self, proxy: str, new_admin: str) -> any:
        """Validate the inputs to the changeProxyAdmin method."""
        self.validator.assert_valid(
            method_name='changeProxyAdmin',
            parameter_name='proxy',
            argument_value=proxy,
        )
        proxy = self.validate_and_checksum_address(proxy)
        self.validator.assert_valid(
            method_name='changeProxyAdmin',
            parameter_name='newAdmin',
            argument_value=new_admin,
        )
        new_admin = self.validate_and_checksum_address(new_admin)
        return (proxy, new_admin)

    def block_send(self, proxy: str, new_admin: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(proxy, new_admin)
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

                self._on_receipt_handle("change_proxy_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: change_proxy_admin")
            message = f"Error {er}: change_proxy_admin"
            self._on_fail("change_proxy_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, change_proxy_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, change_proxy_admin. Reason: Unknown")

            self._on_fail("change_proxy_admin", message)

    def send_transaction(self, proxy: str, new_admin: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (proxy, new_admin) = self.validate_and_normalize_inputs(proxy, new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, new_admin).transact(tx_params.as_dict())

    def build_transaction(self, proxy: str, new_admin: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (proxy, new_admin) = self.validate_and_normalize_inputs(proxy, new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, new_admin).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, proxy: str, new_admin: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (proxy, new_admin) = self.validate_and_normalize_inputs(proxy, new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, new_admin).estimateGas(tx_params.as_dict())


class GetProxyAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getProxyAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getProxyAdmin")

    def validate_and_normalize_inputs(self, proxy: str) -> any:
        """Validate the inputs to the getProxyAdmin method."""
        self.validator.assert_valid(
            method_name='getProxyAdmin',
            parameter_name='proxy',
            argument_value=proxy,
        )
        proxy = self.validate_and_checksum_address(proxy)
        return (proxy)

    def block_call(self, proxy: str, debug: bool = False) -> str:
        _fn = self._underlying_method(proxy)
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def block_send(self, proxy: str, _valeth: int = 0) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(proxy)
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

                self._on_receipt_handle("get_proxy_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_proxy_admin")
            message = f"Error {er}: get_proxy_admin"
            self._on_fail("get_proxy_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_proxy_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_proxy_admin. Reason: Unknown")

            self._on_fail("get_proxy_admin", message)

    def send_transaction(self, proxy: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).transact(tx_params.as_dict())

    def build_transaction(self, proxy: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, proxy: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).estimateGas(tx_params.as_dict())


class GetProxyImplementationMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getProxyImplementation method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getProxyImplementation")

    def validate_and_normalize_inputs(self, proxy: str) -> any:
        """Validate the inputs to the getProxyImplementation method."""
        self.validator.assert_valid(
            method_name='getProxyImplementation',
            parameter_name='proxy',
            argument_value=proxy,
        )
        proxy = self.validate_and_checksum_address(proxy)
        return (proxy)

    def block_call(self, proxy: str, debug: bool = False) -> str:
        _fn = self._underlying_method(proxy)
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def block_send(self, proxy: str, _valeth: int = 0) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(proxy)
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

                self._on_receipt_handle("get_proxy_implementation", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_proxy_implementation")
            message = f"Error {er}: get_proxy_implementation"
            self._on_fail("get_proxy_implementation", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_proxy_implementation: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_proxy_implementation. Reason: Unknown")

            self._on_fail("get_proxy_implementation", message)

    def send_transaction(self, proxy: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).transact(tx_params.as_dict())

    def build_transaction(self, proxy: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, proxy: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (proxy) = self.validate_and_normalize_inputs(proxy)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy).estimateGas(tx_params.as_dict())


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


class UpgradeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the upgrade method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("upgrade")

    def validate_and_normalize_inputs(self, proxy: str, implementation: str) -> any:
        """Validate the inputs to the upgrade method."""
        self.validator.assert_valid(
            method_name='upgrade',
            parameter_name='proxy',
            argument_value=proxy,
        )
        proxy = self.validate_and_checksum_address(proxy)
        self.validator.assert_valid(
            method_name='upgrade',
            parameter_name='implementation',
            argument_value=implementation,
        )
        implementation = self.validate_and_checksum_address(implementation)
        return (proxy, implementation)

    def block_send(self, proxy: str, implementation: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(proxy, implementation)
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

                self._on_receipt_handle("upgrade", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: upgrade")
            message = f"Error {er}: upgrade"
            self._on_fail("upgrade", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade. Reason: Unknown")

            self._on_fail("upgrade", message)

    def send_transaction(self, proxy: str, implementation: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (proxy, implementation) = self.validate_and_normalize_inputs(proxy, implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation).transact(tx_params.as_dict())

    def build_transaction(self, proxy: str, implementation: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (proxy, implementation) = self.validate_and_normalize_inputs(proxy, implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, proxy: str, implementation: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (proxy, implementation) = self.validate_and_normalize_inputs(proxy, implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation).estimateGas(tx_params.as_dict())


class UpgradeAndCallMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the upgradeAndCall method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("upgradeAndCall")

    def validate_and_normalize_inputs(self, proxy: str, implementation: str, data: Union[bytes, str]) -> any:
        """Validate the inputs to the upgradeAndCall method."""
        self.validator.assert_valid(
            method_name='upgradeAndCall',
            parameter_name='proxy',
            argument_value=proxy,
        )
        proxy = self.validate_and_checksum_address(proxy)
        self.validator.assert_valid(
            method_name='upgradeAndCall',
            parameter_name='implementation',
            argument_value=implementation,
        )
        implementation = self.validate_and_checksum_address(implementation)
        self.validator.assert_valid(
            method_name='upgradeAndCall',
            parameter_name='data',
            argument_value=data,
        )
        return (proxy, implementation, data)

    def block_send(self, proxy: str, implementation: str, data: Union[bytes, str], _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(proxy, implementation, data)
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

                self._on_receipt_handle("upgrade_and_call", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: upgrade_and_call")
            message = f"Error {er}: upgrade_and_call"
            self._on_fail("upgrade_and_call", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_and_call: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_and_call. Reason: Unknown")

            self._on_fail("upgrade_and_call", message)

    def send_transaction(self, proxy: str, implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (proxy, implementation, data) = self.validate_and_normalize_inputs(proxy, implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation, data).transact(tx_params.as_dict())

    def build_transaction(self, proxy: str, implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (proxy, implementation, data) = self.validate_and_normalize_inputs(proxy, implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation, data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, proxy: str, implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (proxy, implementation, data) = self.validate_and_normalize_inputs(proxy, implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(proxy, implementation, data).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def change_proxy_admin(self) -> str:
        return self._function_signatures["changeProxyAdmin"]

    def get_proxy_admin(self) -> str:
        return self._function_signatures["getProxyAdmin"]

    def get_proxy_implementation(self) -> str:
        return self._function_signatures["getProxyImplementation"]

    def owner(self) -> str:
        return self._function_signatures["owner"]

    def renounce_ownership(self) -> str:
        return self._function_signatures["renounceOwnership"]

    def transfer_ownership(self) -> str:
        return self._function_signatures["transferOwnership"]

    def upgrade(self) -> str:
        return self._function_signatures["upgrade"]

    def upgrade_and_call(self) -> str:
        return self._function_signatures["upgradeAndCall"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class ProxyAdmin(ContractBase):
    """Wrapper class for ProxyAdmin Solidity contract.

    All method parameters of type `bytes`:code: should be encoded as UTF-8,
    which can be accomplished via `str.encode("utf_8")`:code:.
    """
    _fn_change_proxy_admin: ChangeProxyAdminMethod
    """Constructor-initialized instance of
    :class:`ChangeProxyAdminMethod`.
    """

    _fn_get_proxy_admin: GetProxyAdminMethod
    """Constructor-initialized instance of
    :class:`GetProxyAdminMethod`.
    """

    _fn_get_proxy_implementation: GetProxyImplementationMethod
    """Constructor-initialized instance of
    :class:`GetProxyImplementationMethod`.
    """

    _fn_owner: OwnerMethod
    """Constructor-initialized instance of
    :class:`OwnerMethod`.
    """

    _fn_renounce_ownership: RenounceOwnershipMethod
    """Constructor-initialized instance of
    :class:`RenounceOwnershipMethod`.
    """

    _fn_transfer_ownership: TransferOwnershipMethod
    """Constructor-initialized instance of
    :class:`TransferOwnershipMethod`.
    """

    _fn_upgrade: UpgradeMethod
    """Constructor-initialized instance of
    :class:`UpgradeMethod`.
    """

    _fn_upgrade_and_call: UpgradeAndCallMethod
    """Constructor-initialized instance of
    :class:`UpgradeAndCallMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: ProxyAdminValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, ProxyAdmin.abi())
        web3 = core_lib.w3

        if not validator:
            validator = ProxyAdminValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=ProxyAdmin.abi()).functions
        self._signatures = SignatureGenerator(ProxyAdmin.abi())
        validator.bindSignatures(self._signatures)

        self._fn_change_proxy_admin = ChangeProxyAdminMethod(core_lib, contract_address, functions.changeProxyAdmin, validator)
        self._fn_get_proxy_admin = GetProxyAdminMethod(core_lib, contract_address, functions.getProxyAdmin, validator)
        self._fn_get_proxy_implementation = GetProxyImplementationMethod(core_lib, contract_address, functions.getProxyImplementation, validator)
        self._fn_owner = OwnerMethod(core_lib, contract_address, functions.owner, validator)
        self._fn_renounce_ownership = RenounceOwnershipMethod(core_lib, contract_address, functions.renounceOwnership, validator)
        self._fn_transfer_ownership = TransferOwnershipMethod(core_lib, contract_address, functions.transferOwnership, validator)
        self._fn_upgrade = UpgradeMethod(core_lib, contract_address, functions.upgrade, validator)
        self._fn_upgrade_and_call = UpgradeAndCallMethod(core_lib, contract_address, functions.upgradeAndCall, validator)

    def event_ownership_transferred(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event ownership_transferred in contract ProxyAdmin
        Get log entry for OwnershipTransferred event.
                :param tx_hash: hash of transaction emitting OwnershipTransferred event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=ProxyAdmin.abi()).events.OwnershipTransferred().processReceipt(tx_receipt)

    def change_proxy_admin(self, proxy: str, new_admin: str) -> None:
        """
        Implementation of change_proxy_admin in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_change_proxy_admin.callback_onfail = self._callback_onfail
        self._fn_change_proxy_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_change_proxy_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_change_proxy_admin.gas_limit = self.call_contract_fee_amount
        self._fn_change_proxy_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_change_proxy_admin.debug_method = self.call_contract_debug_flag

        return self._fn_change_proxy_admin.block_send(proxy, new_admin)

    def get_proxy_admin(self, proxy: str) -> str:
        """
        Implementation of get_proxy_admin in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_get_proxy_admin.callback_onfail = self._callback_onfail
        self._fn_get_proxy_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_get_proxy_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_proxy_admin.gas_limit = self.call_contract_fee_amount
        self._fn_get_proxy_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_get_proxy_admin.debug_method = self.call_contract_debug_flag

        return self._fn_get_proxy_admin.block_call(proxy)

    def get_proxy_implementation(self, proxy: str) -> str:
        """
        Implementation of get_proxy_implementation in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_get_proxy_implementation.callback_onfail = self._callback_onfail
        self._fn_get_proxy_implementation.callback_onsuccess = self._callback_onsuccess
        self._fn_get_proxy_implementation.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_proxy_implementation.gas_limit = self.call_contract_fee_amount
        self._fn_get_proxy_implementation.gas_price_wei = self.call_contract_fee_price
        self._fn_get_proxy_implementation.debug_method = self.call_contract_debug_flag

        return self._fn_get_proxy_implementation.block_call(proxy)

    def owner(self) -> str:
        """
        Implementation of owner in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_owner.callback_onfail = self._callback_onfail
        self._fn_owner.callback_onsuccess = self._callback_onsuccess
        self._fn_owner.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_owner.gas_limit = self.call_contract_fee_amount
        self._fn_owner.gas_price_wei = self.call_contract_fee_price
        self._fn_owner.debug_method = self.call_contract_debug_flag

        return self._fn_owner.block_call()

    def renounce_ownership(self) -> None:
        """
        Implementation of renounce_ownership in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_renounce_ownership.callback_onfail = self._callback_onfail
        self._fn_renounce_ownership.callback_onsuccess = self._callback_onsuccess
        self._fn_renounce_ownership.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_renounce_ownership.gas_limit = self.call_contract_fee_amount
        self._fn_renounce_ownership.gas_price_wei = self.call_contract_fee_price
        self._fn_renounce_ownership.debug_method = self.call_contract_debug_flag

        return self._fn_renounce_ownership.block_send()

    def transfer_ownership(self, new_owner: str) -> None:
        """
        Implementation of transfer_ownership in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_transfer_ownership.callback_onfail = self._callback_onfail
        self._fn_transfer_ownership.callback_onsuccess = self._callback_onsuccess
        self._fn_transfer_ownership.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_transfer_ownership.gas_limit = self.call_contract_fee_amount
        self._fn_transfer_ownership.gas_price_wei = self.call_contract_fee_price
        self._fn_transfer_ownership.debug_method = self.call_contract_debug_flag

        return self._fn_transfer_ownership.block_send(new_owner)

    def upgrade(self, proxy: str, implementation: str) -> None:
        """
        Implementation of upgrade in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_upgrade.callback_onfail = self._callback_onfail
        self._fn_upgrade.callback_onsuccess = self._callback_onsuccess
        self._fn_upgrade.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_upgrade.gas_limit = self.call_contract_fee_amount
        self._fn_upgrade.gas_price_wei = self.call_contract_fee_price
        self._fn_upgrade.debug_method = self.call_contract_debug_flag

        return self._fn_upgrade.block_send(proxy, implementation)

    def upgrade_and_call(self, proxy: str, implementation: str, data: Union[bytes, str], wei: int = 0) -> None:
        """
        Implementation of upgrade_and_call in contract ProxyAdmin
        Method of the function
    
        """

        self._fn_upgrade_and_call.callback_onfail = self._callback_onfail
        self._fn_upgrade_and_call.callback_onsuccess = self._callback_onsuccess
        self._fn_upgrade_and_call.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_upgrade_and_call.gas_limit = self.call_contract_fee_amount
        self._fn_upgrade_and_call.gas_price_wei = self.call_contract_fee_price
        self._fn_upgrade_and_call.debug_method = self.call_contract_debug_flag

        self._fn_upgrade_and_call.wei_value = wei

        return self._fn_upgrade_and_call.block_send(proxy, implementation, data, wei)

    def CallContractWait(self, t_long: int) -> "ProxyAdmin":
        self._fn_change_proxy_admin.setWait(t_long)
        self._fn_get_proxy_admin.setWait(t_long)
        self._fn_get_proxy_implementation.setWait(t_long)
        self._fn_owner.setWait(t_long)
        self._fn_renounce_ownership.setWait(t_long)
        self._fn_transfer_ownership.setWait(t_long)
        self._fn_upgrade.setWait(t_long)
        self._fn_upgrade_and_call.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[{"internalType":"contract TransparentUpgradeableProxy","name":"proxy","type":"address"},{"internalType":"address","name":"newAdmin","type":"address"}],"name":"changeProxyAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"contract TransparentUpgradeableProxy","name":"proxy","type":"address"}],"name":"getProxyAdmin","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"contract TransparentUpgradeableProxy","name":"proxy","type":"address"}],"name":"getProxyImplementation","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"contract TransparentUpgradeableProxy","name":"proxy","type":"address"},{"internalType":"address","name":"implementation","type":"address"}],"name":"upgrade","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"contract TransparentUpgradeableProxy","name":"proxy","type":"address"},{"internalType":"address","name":"implementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeAndCall","outputs":[],"stateMutability":"payable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
