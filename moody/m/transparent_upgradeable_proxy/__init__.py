"""Generated wrapper for TransparentUpgradeableProxy Solidity contract."""

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
# constructor for TransparentUpgradeableProxy below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        TransparentUpgradeableProxyValidator,
    )
except ImportError:

    class TransparentUpgradeableProxyValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the admin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("admin")

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

                self._on_receipt_handle("admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: admin")
            message = f"Error {er}: admin"
            self._on_fail("admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, admin. Reason: Unknown")

            self._on_fail("admin", message)

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


class ChangeAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the changeAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("changeAdmin")

    def validate_and_normalize_inputs(self, new_admin: str) -> any:
        """Validate the inputs to the changeAdmin method."""
        self.validator.assert_valid(
            method_name='changeAdmin',
            parameter_name='newAdmin',
            argument_value=new_admin,
        )
        new_admin = self.validate_and_checksum_address(new_admin)
        return (new_admin)

    def block_send(self, new_admin: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_admin)
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

                self._on_receipt_handle("change_admin", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: change_admin")
            message = f"Error {er}: change_admin"
            self._on_fail("change_admin", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, change_admin: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, change_admin. Reason: Unknown")

            self._on_fail("change_admin", message)

    def send_transaction(self, new_admin: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_admin) = self.validate_and_normalize_inputs(new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_admin).transact(tx_params.as_dict())

    def build_transaction(self, new_admin: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_admin) = self.validate_and_normalize_inputs(new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_admin).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_admin: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_admin) = self.validate_and_normalize_inputs(new_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_admin).estimateGas(tx_params.as_dict())


class ImplementationMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the implementation method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("implementation")

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

                self._on_receipt_handle("implementation", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: implementation")
            message = f"Error {er}: implementation"
            self._on_fail("implementation", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, implementation: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, implementation. Reason: Unknown")

            self._on_fail("implementation", message)

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


class UpgradeToMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the upgradeTo method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("upgradeTo")

    def validate_and_normalize_inputs(self, new_implementation: str) -> any:
        """Validate the inputs to the upgradeTo method."""
        self.validator.assert_valid(
            method_name='upgradeTo',
            parameter_name='newImplementation',
            argument_value=new_implementation,
        )
        new_implementation = self.validate_and_checksum_address(new_implementation)
        return (new_implementation)

    def block_send(self, new_implementation: str, _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_implementation)
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

                self._on_receipt_handle("upgrade_to", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: upgrade_to")
            message = f"Error {er}: upgrade_to"
            self._on_fail("upgrade_to", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_to: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_to. Reason: Unknown")

            self._on_fail("upgrade_to", message)

    def send_transaction(self, new_implementation: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_implementation) = self.validate_and_normalize_inputs(new_implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation).transact(tx_params.as_dict())

    def build_transaction(self, new_implementation: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_implementation) = self.validate_and_normalize_inputs(new_implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_implementation: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_implementation) = self.validate_and_normalize_inputs(new_implementation)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation).estimateGas(tx_params.as_dict())


class UpgradeToAndCallMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the upgradeToAndCall method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("upgradeToAndCall")

    def validate_and_normalize_inputs(self, new_implementation: str, data: Union[bytes, str]) -> any:
        """Validate the inputs to the upgradeToAndCall method."""
        self.validator.assert_valid(
            method_name='upgradeToAndCall',
            parameter_name='newImplementation',
            argument_value=new_implementation,
        )
        new_implementation = self.validate_and_checksum_address(new_implementation)
        self.validator.assert_valid(
            method_name='upgradeToAndCall',
            parameter_name='data',
            argument_value=data,
        )
        return (new_implementation, data)

    def block_send(self, new_implementation: str, data: Union[bytes, str], _valeth: int = 0) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_implementation, data)
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

                self._on_receipt_handle("upgrade_to_and_call", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: upgrade_to_and_call")
            message = f"Error {er}: upgrade_to_and_call"
            self._on_fail("upgrade_to_and_call", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_to_and_call: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, upgrade_to_and_call. Reason: Unknown")

            self._on_fail("upgrade_to_and_call", message)

    def send_transaction(self, new_implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_implementation, data) = self.validate_and_normalize_inputs(new_implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation, data).transact(tx_params.as_dict())

    def build_transaction(self, new_implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_implementation, data) = self.validate_and_normalize_inputs(new_implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation, data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_implementation: str, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_implementation, data) = self.validate_and_normalize_inputs(new_implementation, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_implementation, data).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def admin(self) -> str:
        return self._function_signatures["admin"]

    def change_admin(self) -> str:
        return self._function_signatures["changeAdmin"]

    def implementation(self) -> str:
        return self._function_signatures["implementation"]

    def upgrade_to(self) -> str:
        return self._function_signatures["upgradeTo"]

    def upgrade_to_and_call(self) -> str:
        return self._function_signatures["upgradeToAndCall"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class TransparentUpgradeableProxy(ContractBase):
    """Wrapper class for TransparentUpgradeableProxy Solidity contract.

    All method parameters of type `bytes`:code: should be encoded as UTF-8,
    which can be accomplished via `str.encode("utf_8")`:code:.
    """
    _fn_admin: AdminMethod
    """Constructor-initialized instance of
    :class:`AdminMethod`.
    """

    _fn_change_admin: ChangeAdminMethod
    """Constructor-initialized instance of
    :class:`ChangeAdminMethod`.
    """

    _fn_implementation: ImplementationMethod
    """Constructor-initialized instance of
    :class:`ImplementationMethod`.
    """

    _fn_upgrade_to: UpgradeToMethod
    """Constructor-initialized instance of
    :class:`UpgradeToMethod`.
    """

    _fn_upgrade_to_and_call: UpgradeToAndCallMethod
    """Constructor-initialized instance of
    :class:`UpgradeToAndCallMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: TransparentUpgradeableProxyValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, TransparentUpgradeableProxy.abi())
        web3 = core_lib.w3

        if not validator:
            validator = TransparentUpgradeableProxyValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=TransparentUpgradeableProxy.abi()).functions
        self._signatures = SignatureGenerator(TransparentUpgradeableProxy.abi())
        validator.bindSignatures(self._signatures)

        self._fn_admin = AdminMethod(core_lib, contract_address, functions.admin, validator)
        self._fn_change_admin = ChangeAdminMethod(core_lib, contract_address, functions.changeAdmin, validator)
        self._fn_implementation = ImplementationMethod(core_lib, contract_address, functions.implementation, validator)
        self._fn_upgrade_to = UpgradeToMethod(core_lib, contract_address, functions.upgradeTo, validator)
        self._fn_upgrade_to_and_call = UpgradeToAndCallMethod(core_lib, contract_address, functions.upgradeToAndCall, validator)

    def event_admin_changed(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event admin_changed in contract TransparentUpgradeableProxy
        Get log entry for AdminChanged event.
                :param tx_hash: hash of transaction emitting AdminChanged event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=TransparentUpgradeableProxy.abi()).events.AdminChanged().processReceipt(tx_receipt)

    def event_beacon_upgraded(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event beacon_upgraded in contract TransparentUpgradeableProxy
        Get log entry for BeaconUpgraded event.
                :param tx_hash: hash of transaction emitting BeaconUpgraded event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=TransparentUpgradeableProxy.abi()).events.BeaconUpgraded().processReceipt(tx_receipt)

    def event_upgraded(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event upgraded in contract TransparentUpgradeableProxy
        Get log entry for Upgraded event.
                :param tx_hash: hash of transaction emitting Upgraded event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=TransparentUpgradeableProxy.abi()).events.Upgraded().processReceipt(tx_receipt)

    def admin(self) -> str:
        """
        Implementation of admin in contract TransparentUpgradeableProxy
        Method of the function
    
        """

        self._fn_admin.callback_onfail = self._callback_onfail
        self._fn_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_admin.gas_limit = self.call_contract_fee_amount
        self._fn_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_admin.debug_method = self.call_contract_debug_flag

        return self._fn_admin.block_send()

    def change_admin(self, new_admin: str) -> None:
        """
        Implementation of change_admin in contract TransparentUpgradeableProxy
        Method of the function
    
        """

        self._fn_change_admin.callback_onfail = self._callback_onfail
        self._fn_change_admin.callback_onsuccess = self._callback_onsuccess
        self._fn_change_admin.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_change_admin.gas_limit = self.call_contract_fee_amount
        self._fn_change_admin.gas_price_wei = self.call_contract_fee_price
        self._fn_change_admin.debug_method = self.call_contract_debug_flag

        return self._fn_change_admin.block_send(new_admin)

    def implementation(self) -> str:
        """
        Implementation of implementation in contract TransparentUpgradeableProxy
        Method of the function
    
        """

        self._fn_implementation.callback_onfail = self._callback_onfail
        self._fn_implementation.callback_onsuccess = self._callback_onsuccess
        self._fn_implementation.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_implementation.gas_limit = self.call_contract_fee_amount
        self._fn_implementation.gas_price_wei = self.call_contract_fee_price
        self._fn_implementation.debug_method = self.call_contract_debug_flag

        return self._fn_implementation.block_send()

    def upgrade_to(self, new_implementation: str) -> None:
        """
        Implementation of upgrade_to in contract TransparentUpgradeableProxy
        Method of the function
    
        """

        self._fn_upgrade_to.callback_onfail = self._callback_onfail
        self._fn_upgrade_to.callback_onsuccess = self._callback_onsuccess
        self._fn_upgrade_to.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_upgrade_to.gas_limit = self.call_contract_fee_amount
        self._fn_upgrade_to.gas_price_wei = self.call_contract_fee_price
        self._fn_upgrade_to.debug_method = self.call_contract_debug_flag

        return self._fn_upgrade_to.block_send(new_implementation)

    def upgrade_to_and_call(self, new_implementation: str, data: Union[bytes, str], wei: int = 0) -> None:
        """
        Implementation of upgrade_to_and_call in contract TransparentUpgradeableProxy
        Method of the function
    
        """

        self._fn_upgrade_to_and_call.callback_onfail = self._callback_onfail
        self._fn_upgrade_to_and_call.callback_onsuccess = self._callback_onsuccess
        self._fn_upgrade_to_and_call.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_upgrade_to_and_call.gas_limit = self.call_contract_fee_amount
        self._fn_upgrade_to_and_call.gas_price_wei = self.call_contract_fee_price
        self._fn_upgrade_to_and_call.debug_method = self.call_contract_debug_flag

        self._fn_upgrade_to_and_call.wei_value = wei

        return self._fn_upgrade_to_and_call.block_send(new_implementation, data, wei)

    def CallContractWait(self, t_long: int) -> "TransparentUpgradeableProxy":
        self._fn_admin.setWait(t_long)
        self._fn_change_admin.setWait(t_long)
        self._fn_implementation.setWait(t_long)
        self._fn_upgrade_to.setWait(t_long)
        self._fn_upgrade_to_and_call.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"_logic","type":"address"},{"internalType":"address","name":"admin_","type":"address"},{"internalType":"bytes","name":"_data","type":"bytes"}],"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"previousAdmin","type":"address"},{"indexed":false,"internalType":"address","name":"newAdmin","type":"address"}],"name":"AdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"beacon","type":"address"}],"name":"BeaconUpgraded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Upgraded","type":"event"},{"stateMutability":"payable","type":"fallback"},{"inputs":[],"name":"admin","outputs":[{"internalType":"address","name":"admin_","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newAdmin","type":"address"}],"name":"changeAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"implementation","outputs":[{"internalType":"address","name":"implementation_","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"}],"name":"upgradeTo","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"},{"stateMutability":"payable","type":"receive"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
