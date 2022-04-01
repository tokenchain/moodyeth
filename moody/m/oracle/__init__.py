"""Generated wrapper for Oracle Solidity contract."""

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
# constructor for Oracle below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        OracleValidator,
    )
except ImportError:

    class OracleValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class ExpiryTimeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the EXPIRY_TIME method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("EXPIRY_TIME")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: expiry_time")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, expiry_time: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, expiry_time. Reason: Unknown")

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


class CancelOracleRequestMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the cancelOracleRequest method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("cancelOracleRequest")

    def validate_and_normalize_inputs(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int) -> any:
        """Validate the inputs to the cancelOracleRequest method."""
        self.validator.assert_valid(
            method_name='cancelOracleRequest',
            parameter_name='_requestId',
            argument_value=request_id,
        )
        self.validator.assert_valid(
            method_name='cancelOracleRequest',
            parameter_name='_payment',
            argument_value=payment,
        )
        # safeguard against fractional inputs
        payment = int(payment)
        self.validator.assert_valid(
            method_name='cancelOracleRequest',
            parameter_name='_callbackFunc',
            argument_value=callback_func,
        )
        self.validator.assert_valid(
            method_name='cancelOracleRequest',
            parameter_name='_expiration',
            argument_value=expiration,
        )
        # safeguard against fractional inputs
        expiration = int(expiration)
        return (request_id, payment, callback_func, expiration)

    def block_send(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(request_id, payment, callback_func, expiration)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: cancel_oracle_request")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, cancel_oracle_request: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, cancel_oracle_request. Reason: Unknown")

    def send_transaction(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (request_id, payment, callback_func, expiration) = self.validate_and_normalize_inputs(request_id, payment, callback_func, expiration)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_func, expiration).transact(tx_params.as_dict())

    def build_transaction(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (request_id, payment, callback_func, expiration) = self.validate_and_normalize_inputs(request_id, payment, callback_func, expiration)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_func, expiration).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (request_id, payment, callback_func, expiration) = self.validate_and_normalize_inputs(request_id, payment, callback_func, expiration)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_func, expiration).estimateGas(tx_params.as_dict())


class FulfillOracleRequestMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the fulfillOracleRequest method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("fulfillOracleRequest")

    def validate_and_normalize_inputs(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str]) -> any:
        """Validate the inputs to the fulfillOracleRequest method."""
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_requestId',
            argument_value=request_id,
        )
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_payment',
            argument_value=payment,
        )
        # safeguard against fractional inputs
        payment = int(payment)
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_callbackAddress',
            argument_value=callback_address,
        )
        callback_address = self.validate_and_checksum_address(callback_address)
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_callbackFunctionId',
            argument_value=callback_function_id,
        )
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_expiration',
            argument_value=expiration,
        )
        # safeguard against fractional inputs
        expiration = int(expiration)
        self.validator.assert_valid(
            method_name='fulfillOracleRequest',
            parameter_name='_data',
            argument_value=data,
        )
        return (request_id, payment, callback_address, callback_function_id, expiration, data)

    def block_send(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str], _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(request_id, payment, callback_address, callback_function_id, expiration, data)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: fulfill_oracle_request")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fulfill_oracle_request: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fulfill_oracle_request. Reason: Unknown")

    def send_transaction(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (request_id, payment, callback_address, callback_function_id, expiration, data) = self.validate_and_normalize_inputs(request_id, payment, callback_address, callback_function_id, expiration, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_address, callback_function_id, expiration, data).transact(tx_params.as_dict())

    def build_transaction(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (request_id, payment, callback_address, callback_function_id, expiration, data) = self.validate_and_normalize_inputs(request_id, payment, callback_address, callback_function_id, expiration, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_address, callback_function_id, expiration, data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (request_id, payment, callback_address, callback_function_id, expiration, data) = self.validate_and_normalize_inputs(request_id, payment, callback_address, callback_function_id, expiration, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, payment, callback_address, callback_function_id, expiration, data).estimateGas(tx_params.as_dict())


class GetAuthorizationStatusMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getAuthorizationStatus method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAuthorizationStatus")

    def validate_and_normalize_inputs(self, node: str) -> any:
        """Validate the inputs to the getAuthorizationStatus method."""
        self.validator.assert_valid(
            method_name='getAuthorizationStatus',
            parameter_name='_node',
            argument_value=node,
        )
        node = self.validate_and_checksum_address(node)
        return (node)

    def block_call(self, node: str, debug: bool = False) -> bool:
        _fn = self._underlying_method(node)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def block_send(self, node: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(node)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_authorization_status")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_authorization_status: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_authorization_status. Reason: Unknown")

    def send_transaction(self, node: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (node) = self.validate_and_normalize_inputs(node)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node).transact(tx_params.as_dict())

    def build_transaction(self, node: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (node) = self.validate_and_normalize_inputs(node)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, node: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (node) = self.validate_and_normalize_inputs(node)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node).estimateGas(tx_params.as_dict())


class GetChainlinkTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getChainlinkToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getChainlinkToken")

    def block_call(self, debug: bool = False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def block_send(self, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_chainlink_token")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_chainlink_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_chainlink_token. Reason: Unknown")

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

    def block_send(self, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: is_owner")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_owner: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, is_owner. Reason: Unknown")

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


class OnTokenTransferMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the onTokenTransfer method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("onTokenTransfer")

    def validate_and_normalize_inputs(self, sender: str, amount: int, data: Union[bytes, str]) -> any:
        """Validate the inputs to the onTokenTransfer method."""
        self.validator.assert_valid(
            method_name='onTokenTransfer',
            parameter_name='_sender',
            argument_value=sender,
        )
        sender = self.validate_and_checksum_address(sender)
        self.validator.assert_valid(
            method_name='onTokenTransfer',
            parameter_name='_amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        self.validator.assert_valid(
            method_name='onTokenTransfer',
            parameter_name='_data',
            argument_value=data,
        )
        return (sender, amount, data)

    def block_send(self, sender: str, amount: int, data: Union[bytes, str], _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(sender, amount, data)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: on_token_transfer")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, on_token_transfer: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, on_token_transfer. Reason: Unknown")

    def send_transaction(self, sender: str, amount: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (sender, amount, data) = self.validate_and_normalize_inputs(sender, amount, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, amount, data).transact(tx_params.as_dict())

    def build_transaction(self, sender: str, amount: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (sender, amount, data) = self.validate_and_normalize_inputs(sender, amount, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, amount, data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, sender: str, amount: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (sender, amount, data) = self.validate_and_normalize_inputs(sender, amount, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, amount, data).estimateGas(tx_params.as_dict())


class OracleRequestMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the oracleRequest method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("oracleRequest")

    def validate_and_normalize_inputs(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str]) -> any:
        """Validate the inputs to the oracleRequest method."""
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_sender',
            argument_value=sender,
        )
        sender = self.validate_and_checksum_address(sender)
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_payment',
            argument_value=payment,
        )
        # safeguard against fractional inputs
        payment = int(payment)
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_specId',
            argument_value=spec_id,
        )
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_callbackAddress',
            argument_value=callback_address,
        )
        callback_address = self.validate_and_checksum_address(callback_address)
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_callbackFunctionId',
            argument_value=callback_function_id,
        )
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_nonce',
            argument_value=nonce,
        )
        # safeguard against fractional inputs
        nonce = int(nonce)
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_dataVersion',
            argument_value=data_version,
        )
        # safeguard against fractional inputs
        data_version = int(data_version)
        self.validator.assert_valid(
            method_name='oracleRequest',
            parameter_name='_data',
            argument_value=data,
        )
        return (sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data)

    def block_send(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str], _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: oracle_request")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, oracle_request: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, oracle_request. Reason: Unknown")

    def send_transaction(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data) = self.validate_and_normalize_inputs(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data).transact(tx_params.as_dict())

    def build_transaction(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data) = self.validate_and_normalize_inputs(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data) = self.validate_and_normalize_inputs(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data).estimateGas(tx_params.as_dict())


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

    def block_send(self, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: owner")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, owner: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, owner. Reason: Unknown")

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


class SetFulfillmentPermissionMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setFulfillmentPermission method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setFulfillmentPermission")

    def validate_and_normalize_inputs(self, node: str, allowed: bool) -> any:
        """Validate the inputs to the setFulfillmentPermission method."""
        self.validator.assert_valid(
            method_name='setFulfillmentPermission',
            parameter_name='_node',
            argument_value=node,
        )
        node = self.validate_and_checksum_address(node)
        self.validator.assert_valid(
            method_name='setFulfillmentPermission',
            parameter_name='_allowed',
            argument_value=allowed,
        )
        return (node, allowed)

    def block_send(self, node: str, allowed: bool, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(node, allowed)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_fulfillment_permission")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fulfillment_permission: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fulfillment_permission. Reason: Unknown")

    def send_transaction(self, node: str, allowed: bool, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (node, allowed) = self.validate_and_normalize_inputs(node, allowed)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node, allowed).transact(tx_params.as_dict())

    def build_transaction(self, node: str, allowed: bool, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (node, allowed) = self.validate_and_normalize_inputs(node, allowed)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node, allowed).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, node: str, allowed: bool, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (node, allowed) = self.validate_and_normalize_inputs(node, allowed)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(node, allowed).estimateGas(tx_params.as_dict())


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

    def block_send(self, new_owner: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_owner)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer_ownership")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_ownership: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, transfer_ownership. Reason: Unknown")

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


class WithdrawMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdraw method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("withdraw")

    def validate_and_normalize_inputs(self, recipient: str, amount: int) -> any:
        """Validate the inputs to the withdraw method."""
        self.validator.assert_valid(
            method_name='withdraw',
            parameter_name='_recipient',
            argument_value=recipient,
        )
        recipient = self.validate_and_checksum_address(recipient)
        self.validator.assert_valid(
            method_name='withdraw',
            parameter_name='_amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (recipient, amount)

    def block_send(self, recipient: str, amount: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(recipient, amount)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: withdraw")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdraw. Reason: Unknown")

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


class WithdrawableMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdrawable method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("withdrawable")

    def block_call(self, debug: bool = False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def block_send(self, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: withdrawable")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdrawable: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, withdrawable. Reason: Unknown")

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


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def expiry_time(self) -> str:
        return self._function_signatures["EXPIRY_TIME"]

    def cancel_oracle_request(self) -> str:
        return self._function_signatures["cancelOracleRequest"]

    def fulfill_oracle_request(self) -> str:
        return self._function_signatures["fulfillOracleRequest"]

    def get_authorization_status(self) -> str:
        return self._function_signatures["getAuthorizationStatus"]

    def get_chainlink_token(self) -> str:
        return self._function_signatures["getChainlinkToken"]

    def is_owner(self) -> str:
        return self._function_signatures["isOwner"]

    def on_token_transfer(self) -> str:
        return self._function_signatures["onTokenTransfer"]

    def oracle_request(self) -> str:
        return self._function_signatures["oracleRequest"]

    def owner(self) -> str:
        return self._function_signatures["owner"]

    def set_fulfillment_permission(self) -> str:
        return self._function_signatures["setFulfillmentPermission"]

    def transfer_ownership(self) -> str:
        return self._function_signatures["transferOwnership"]

    def withdraw(self) -> str:
        return self._function_signatures["withdraw"]

    def withdrawable(self) -> str:
        return self._function_signatures["withdrawable"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Oracle(ContractBase):
    """Wrapper class for Oracle Solidity contract.

    All method parameters of type `bytes`:code: should be encoded as UTF-8,
    which can be accomplished via `str.encode("utf_8")`:code:.
    """
    _fn_expiry_time: ExpiryTimeMethod
    """Constructor-initialized instance of
    :class:`ExpiryTimeMethod`.
    """

    _fn_cancel_oracle_request: CancelOracleRequestMethod
    """Constructor-initialized instance of
    :class:`CancelOracleRequestMethod`.
    """

    _fn_fulfill_oracle_request: FulfillOracleRequestMethod
    """Constructor-initialized instance of
    :class:`FulfillOracleRequestMethod`.
    """

    _fn_get_authorization_status: GetAuthorizationStatusMethod
    """Constructor-initialized instance of
    :class:`GetAuthorizationStatusMethod`.
    """

    _fn_get_chainlink_token: GetChainlinkTokenMethod
    """Constructor-initialized instance of
    :class:`GetChainlinkTokenMethod`.
    """

    _fn_is_owner: IsOwnerMethod
    """Constructor-initialized instance of
    :class:`IsOwnerMethod`.
    """

    _fn_on_token_transfer: OnTokenTransferMethod
    """Constructor-initialized instance of
    :class:`OnTokenTransferMethod`.
    """

    _fn_oracle_request: OracleRequestMethod
    """Constructor-initialized instance of
    :class:`OracleRequestMethod`.
    """

    _fn_owner: OwnerMethod
    """Constructor-initialized instance of
    :class:`OwnerMethod`.
    """

    _fn_set_fulfillment_permission: SetFulfillmentPermissionMethod
    """Constructor-initialized instance of
    :class:`SetFulfillmentPermissionMethod`.
    """

    _fn_transfer_ownership: TransferOwnershipMethod
    """Constructor-initialized instance of
    :class:`TransferOwnershipMethod`.
    """

    _fn_withdraw: WithdrawMethod
    """Constructor-initialized instance of
    :class:`WithdrawMethod`.
    """

    _fn_withdrawable: WithdrawableMethod
    """Constructor-initialized instance of
    :class:`WithdrawableMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: OracleValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = OracleValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Oracle.abi()).functions
        signed = SignatureGenerator(Oracle.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_expiry_time = ExpiryTimeMethod(core_lib, contract_address, functions.EXPIRY_TIME, validator)
        self._fn_cancel_oracle_request = CancelOracleRequestMethod(core_lib, contract_address, functions.cancelOracleRequest, validator)
        self._fn_fulfill_oracle_request = FulfillOracleRequestMethod(core_lib, contract_address, functions.fulfillOracleRequest, validator)
        self._fn_get_authorization_status = GetAuthorizationStatusMethod(core_lib, contract_address, functions.getAuthorizationStatus, validator)
        self._fn_get_chainlink_token = GetChainlinkTokenMethod(core_lib, contract_address, functions.getChainlinkToken, validator)
        self._fn_is_owner = IsOwnerMethod(core_lib, contract_address, functions.isOwner, validator)
        self._fn_on_token_transfer = OnTokenTransferMethod(core_lib, contract_address, functions.onTokenTransfer, validator)
        self._fn_oracle_request = OracleRequestMethod(core_lib, contract_address, functions.oracleRequest, validator)
        self._fn_owner = OwnerMethod(core_lib, contract_address, functions.owner, validator)
        self._fn_set_fulfillment_permission = SetFulfillmentPermissionMethod(core_lib, contract_address, functions.setFulfillmentPermission, validator)
        self._fn_transfer_ownership = TransferOwnershipMethod(core_lib, contract_address, functions.transferOwnership, validator)
        self._fn_withdraw = WithdrawMethod(core_lib, contract_address, functions.withdraw, validator)
        self._fn_withdrawable = WithdrawableMethod(core_lib, contract_address, functions.withdrawable, validator)

    def event_cancel_oracle_request(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event cancel_oracle_request in contract Oracle
        Get log entry for CancelOracleRequest event.
                :param tx_hash: hash of transaction emitting CancelOracleRequest event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Oracle.abi()).events.CancelOracleRequest().processReceipt(tx_receipt)

    def event_oracle_request(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event oracle_request in contract Oracle
        Get log entry for OracleRequest event.
                :param tx_hash: hash of transaction emitting OracleRequest event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Oracle.abi()).events.OracleRequest().processReceipt(tx_receipt)

    def event_ownership_transferred(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event ownership_transferred in contract Oracle
        Get log entry for OwnershipTransferred event.
                :param tx_hash: hash of transaction emitting OwnershipTransferred event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Oracle.abi()).events.OwnershipTransferred().processReceipt(tx_receipt)

    def expiry_time(self) -> int:
        """
        Implementation of expiry_time in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_expiry_time.block_call()

    def cancel_oracle_request(self, request_id: Union[bytes, str], payment: int, callback_func: Union[bytes, str], expiration: int) -> None:
        """
        Implementation of cancel_oracle_request in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_cancel_oracle_request.block_send(request_id, payment, callback_func, expiration, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def fulfill_oracle_request(self, request_id: Union[bytes, str], payment: int, callback_address: str, callback_function_id: Union[bytes, str], expiration: int, data: Union[bytes, str]) -> bool:
        """
        Implementation of fulfill_oracle_request in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_fulfill_oracle_request.block_send(request_id, payment, callback_address, callback_function_id, expiration, data, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def get_authorization_status(self, node: str) -> bool:
        """
        Implementation of get_authorization_status in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_get_authorization_status.block_call(node)

    def get_chainlink_token(self) -> str:
        """
        Implementation of get_chainlink_token in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_get_chainlink_token.block_call()

    def is_owner(self) -> bool:
        """
        Implementation of is_owner in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_is_owner.block_call()

    def on_token_transfer(self, sender: str, amount: int, data: Union[bytes, str]) -> None:
        """
        Implementation of on_token_transfer in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_on_token_transfer.block_send(sender, amount, data, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def oracle_request(self, sender: str, payment: int, spec_id: Union[bytes, str], callback_address: str, callback_function_id: Union[bytes, str], nonce: int, data_version: int, data: Union[bytes, str]) -> None:
        """
        Implementation of oracle_request in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_oracle_request.block_send(sender, payment, spec_id, callback_address, callback_function_id, nonce, data_version, data, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def owner(self) -> str:
        """
        Implementation of owner in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_owner.block_call()

    def set_fulfillment_permission(self, node: str, allowed: bool) -> None:
        """
        Implementation of set_fulfillment_permission in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_set_fulfillment_permission.block_send(node, allowed, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def transfer_ownership(self, new_owner: str) -> None:
        """
        Implementation of transfer_ownership in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_transfer_ownership.block_send(new_owner, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def withdraw(self, recipient: str, amount: int) -> None:
        """
        Implementation of withdraw in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_withdraw.block_send(recipient, amount, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def withdrawable(self) -> int:
        """
        Implementation of withdrawable in contract Oracle
        Method of the function
    
    
    
        """

        return self._fn_withdrawable.block_call()

    def CallContractWait(self, t_long: int) -> "Oracle":
        self._fn_expiry_time.setWait(t_long)
        self._fn_cancel_oracle_request.setWait(t_long)
        self._fn_fulfill_oracle_request.setWait(t_long)
        self._fn_get_authorization_status.setWait(t_long)
        self._fn_get_chainlink_token.setWait(t_long)
        self._fn_is_owner.setWait(t_long)
        self._fn_on_token_transfer.setWait(t_long)
        self._fn_oracle_request.setWait(t_long)
        self._fn_owner.setWait(t_long)
        self._fn_set_fulfillment_permission.setWait(t_long)
        self._fn_transfer_ownership.setWait(t_long)
        self._fn_withdraw.setWait(t_long)
        self._fn_withdrawable.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"_link","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"requestId","type":"bytes32"}],"name":"CancelOracleRequest","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"specId","type":"bytes32"},{"indexed":false,"internalType":"address","name":"requester","type":"address"},{"indexed":false,"internalType":"bytes32","name":"requestId","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"payment","type":"uint256"},{"indexed":false,"internalType":"address","name":"callbackAddr","type":"address"},{"indexed":false,"internalType":"bytes4","name":"callbackFunctionId","type":"bytes4"},{"indexed":false,"internalType":"uint256","name":"cancelExpiration","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"dataVersion","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"data","type":"bytes"}],"name":"OracleRequest","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[],"name":"EXPIRY_TIME","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_requestId","type":"bytes32"},{"internalType":"uint256","name":"_payment","type":"uint256"},{"internalType":"bytes4","name":"_callbackFunc","type":"bytes4"},{"internalType":"uint256","name":"_expiration","type":"uint256"}],"name":"cancelOracleRequest","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_requestId","type":"bytes32"},{"internalType":"uint256","name":"_payment","type":"uint256"},{"internalType":"address","name":"_callbackAddress","type":"address"},{"internalType":"bytes4","name":"_callbackFunctionId","type":"bytes4"},{"internalType":"uint256","name":"_expiration","type":"uint256"},{"internalType":"bytes32","name":"_data","type":"bytes32"}],"name":"fulfillOracleRequest","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_node","type":"address"}],"name":"getAuthorizationStatus","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getChainlinkToken","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_sender","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"onTokenTransfer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_sender","type":"address"},{"internalType":"uint256","name":"_payment","type":"uint256"},{"internalType":"bytes32","name":"_specId","type":"bytes32"},{"internalType":"address","name":"_callbackAddress","type":"address"},{"internalType":"bytes4","name":"_callbackFunctionId","type":"bytes4"},{"internalType":"uint256","name":"_nonce","type":"uint256"},{"internalType":"uint256","name":"_dataVersion","type":"uint256"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"oracleRequest","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_node","type":"address"},{"internalType":"bool","name":"_allowed","type":"bool"}],"name":"setFulfillmentPermission","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"withdrawable","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
