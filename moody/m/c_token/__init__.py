"""Generated wrapper for CToken Solidity contract."""

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
# constructor for CToken below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        CTokenValidator,
    )
except ImportError:

    class CTokenValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AcceptAdmin_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _acceptAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_acceptAdmin")

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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: accept_admin_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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


class ReduceReserves_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _reduceReserves method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_reduceReserves")

    def validate_and_normalize_inputs(self, reduce_amount: int) -> any:
        """Validate the inputs to the _reduceReserves method."""
        self.validator.assert_valid(
            method_name='_reduceReserves',
            parameter_name='reduceAmount',
            argument_value=reduce_amount,
        )
        # safeguard against fractional inputs
        reduce_amount = int(reduce_amount)
        return (reduce_amount)

    def block_send(self, reduce_amount: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(reduce_amount)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: reduce_reserves_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, reduce_amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (reduce_amount) = self.validate_and_normalize_inputs(reduce_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(reduce_amount).transact(tx_params.as_dict())

    def build_transaction(self, reduce_amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (reduce_amount) = self.validate_and_normalize_inputs(reduce_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(reduce_amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, reduce_amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (reduce_amount) = self.validate_and_normalize_inputs(reduce_amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(reduce_amount).estimateGas(tx_params.as_dict())


class SetComptroller_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _setComptroller method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_setComptroller")

    def validate_and_normalize_inputs(self, new_comptroller: str) -> any:
        """Validate the inputs to the _setComptroller method."""
        self.validator.assert_valid(
            method_name='_setComptroller',
            parameter_name='newComptroller',
            argument_value=new_comptroller,
        )
        new_comptroller = self.validate_and_checksum_address(new_comptroller)
        return (new_comptroller)

    def block_send(self, new_comptroller: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_comptroller)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_comptroller_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, new_comptroller: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_comptroller) = self.validate_and_normalize_inputs(new_comptroller)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_comptroller).transact(tx_params.as_dict())

    def build_transaction(self, new_comptroller: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_comptroller) = self.validate_and_normalize_inputs(new_comptroller)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_comptroller).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_comptroller: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_comptroller) = self.validate_and_normalize_inputs(new_comptroller)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_comptroller).estimateGas(tx_params.as_dict())


class SetInterestRateModel_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _setInterestRateModel method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_setInterestRateModel")

    def validate_and_normalize_inputs(self, new_interest_rate_model: str) -> any:
        """Validate the inputs to the _setInterestRateModel method."""
        self.validator.assert_valid(
            method_name='_setInterestRateModel',
            parameter_name='newInterestRateModel',
            argument_value=new_interest_rate_model,
        )
        new_interest_rate_model = self.validate_and_checksum_address(new_interest_rate_model)
        return (new_interest_rate_model)

    def block_send(self, new_interest_rate_model: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_interest_rate_model)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_interest_rate_model_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, new_interest_rate_model: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_interest_rate_model) = self.validate_and_normalize_inputs(new_interest_rate_model)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_interest_rate_model).transact(tx_params.as_dict())

    def build_transaction(self, new_interest_rate_model: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_interest_rate_model) = self.validate_and_normalize_inputs(new_interest_rate_model)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_interest_rate_model).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_interest_rate_model: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_interest_rate_model) = self.validate_and_normalize_inputs(new_interest_rate_model)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_interest_rate_model).estimateGas(tx_params.as_dict())


class SetPendingAdmin_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _setPendingAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_setPendingAdmin")

    def validate_and_normalize_inputs(self, new_pending_admin: str) -> any:
        """Validate the inputs to the _setPendingAdmin method."""
        self.validator.assert_valid(
            method_name='_setPendingAdmin',
            parameter_name='newPendingAdmin',
            argument_value=new_pending_admin,
        )
        new_pending_admin = self.validate_and_checksum_address(new_pending_admin)
        return (new_pending_admin)

    def block_send(self, new_pending_admin: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_pending_admin)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_pending_admin_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, new_pending_admin: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_pending_admin) = self.validate_and_normalize_inputs(new_pending_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_pending_admin).transact(tx_params.as_dict())

    def build_transaction(self, new_pending_admin: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_pending_admin) = self.validate_and_normalize_inputs(new_pending_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_pending_admin).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_pending_admin: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_pending_admin) = self.validate_and_normalize_inputs(new_pending_admin)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_pending_admin).estimateGas(tx_params.as_dict())


class SetReserveFactor_Method(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the _setReserveFactor method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("_setReserveFactor")

    def validate_and_normalize_inputs(self, new_reserve_factor_mantissa: int) -> any:
        """Validate the inputs to the _setReserveFactor method."""
        self.validator.assert_valid(
            method_name='_setReserveFactor',
            parameter_name='newReserveFactorMantissa',
            argument_value=new_reserve_factor_mantissa,
        )
        # safeguard against fractional inputs
        new_reserve_factor_mantissa = int(new_reserve_factor_mantissa)
        return (new_reserve_factor_mantissa)

    def block_send(self, new_reserve_factor_mantissa: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(new_reserve_factor_mantissa)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_reserve_factor_")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, new_reserve_factor_mantissa: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (new_reserve_factor_mantissa) = self.validate_and_normalize_inputs(new_reserve_factor_mantissa)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_reserve_factor_mantissa).transact(tx_params.as_dict())

    def build_transaction(self, new_reserve_factor_mantissa: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (new_reserve_factor_mantissa) = self.validate_and_normalize_inputs(new_reserve_factor_mantissa)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_reserve_factor_mantissa).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, new_reserve_factor_mantissa: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (new_reserve_factor_mantissa) = self.validate_and_normalize_inputs(new_reserve_factor_mantissa)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(new_reserve_factor_mantissa).estimateGas(tx_params.as_dict())


class AccrualBlockNumberMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the accrualBlockNumber method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("accrualBlockNumber")

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


class AccrueInterestMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the accrueInterest method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("accrueInterest")

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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: accrue_interest")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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


class AdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the admin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("admin")

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

    def block_send(self, spender: str, amount: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(spender, amount)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: approve")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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

    def validate_and_normalize_inputs(self, owner: str) -> any:
        """Validate the inputs to the balanceOf method."""
        self.validator.assert_valid(
            method_name='balanceOf',
            parameter_name='owner',
            argument_value=owner,
        )
        owner = self.validate_and_checksum_address(owner)
        return (owner)

    def block_call(self, owner: str, debug: bool = False) -> int:
        _fn = self._underlying_method(owner)
        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, owner: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (owner) = self.validate_and_normalize_inputs(owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner).estimateGas(tx_params.as_dict())


class BalanceOfUnderlyingMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the balanceOfUnderlying method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("balanceOfUnderlying")

    def validate_and_normalize_inputs(self, owner: str) -> any:
        """Validate the inputs to the balanceOfUnderlying method."""
        self.validator.assert_valid(
            method_name='balanceOfUnderlying',
            parameter_name='owner',
            argument_value=owner,
        )
        owner = self.validate_and_checksum_address(owner)
        return (owner)

    def block_send(self, owner: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(owner)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: balance_of_underlying")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, owner: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (owner) = self.validate_and_normalize_inputs(owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner).transact(tx_params.as_dict())

    def build_transaction(self, owner: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (owner) = self.validate_and_normalize_inputs(owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, owner: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (owner) = self.validate_and_normalize_inputs(owner)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(owner).estimateGas(tx_params.as_dict())


class BorrowBalanceCurrentMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the borrowBalanceCurrent method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("borrowBalanceCurrent")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the borrowBalanceCurrent method."""
        self.validator.assert_valid(
            method_name='borrowBalanceCurrent',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_send(self, account: str, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(account)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: borrow_balance_current")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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


class BorrowBalanceStoredMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the borrowBalanceStored method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("borrowBalanceStored")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the borrowBalanceStored method."""
        self.validator.assert_valid(
            method_name='borrowBalanceStored',
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


class BorrowIndexMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the borrowIndex method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("borrowIndex")

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


class BorrowRatePerBlockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the borrowRatePerBlock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("borrowRatePerBlock")

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


class ComptrollerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the comptroller method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("comptroller")

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


class ExchangeRateCurrentMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the exchangeRateCurrent method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("exchangeRateCurrent")

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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: exchange_rate_current")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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


class ExchangeRateStoredMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the exchangeRateStored method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("exchangeRateStored")

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


class GetAccountSnapshotMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getAccountSnapshot method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAccountSnapshot")

    def validate_and_normalize_inputs(self, account: str) -> any:
        """Validate the inputs to the getAccountSnapshot method."""
        self.validator.assert_valid(
            method_name='getAccountSnapshot',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, debug: bool = False) -> Tuple[int, int, int, int]:
        _fn = self._underlying_method(account)
        returned = _fn.call({
            'from': self._operate
        })
        return (returned[0], returned[1], returned[2], returned[3],)

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class GetCashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCash method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCash")

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


class InitializeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the initialize method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("initialize")

    def validate_and_normalize_inputs(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int) -> any:
        """Validate the inputs to the initialize method."""
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='comptroller_',
            argument_value=comptroller_,
        )
        comptroller_ = self.validate_and_checksum_address(comptroller_)
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='interestRateModel_',
            argument_value=interest_rate_model_,
        )
        interest_rate_model_ = self.validate_and_checksum_address(interest_rate_model_)
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='initialExchangeRateMantissa_',
            argument_value=initial_exchange_rate_mantissa_,
        )
        # safeguard against fractional inputs
        initial_exchange_rate_mantissa_ = int(initial_exchange_rate_mantissa_)
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='name_',
            argument_value=name_,
        )
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='symbol_',
            argument_value=symbol_,
        )
        self.validator.assert_valid(
            method_name='initialize',
            parameter_name='decimals_',
            argument_value=decimals_,
        )
        return (comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_)

    def block_send(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: initialize")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_) = self.validate_and_normalize_inputs(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_).transact(tx_params.as_dict())

    def build_transaction(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_) = self.validate_and_normalize_inputs(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_) = self.validate_and_normalize_inputs(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_).estimateGas(tx_params.as_dict())


class InterestRateModelMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the interestRateModel method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("interestRateModel")

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


class IsCTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isCToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("isCToken")

    def block_call(self, debug: bool = False) -> bool:
        _fn = self._underlying_method()
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


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


class PendingAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the pendingAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("pendingAdmin")

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


class ProtocolSeizeShareMantissaMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the protocolSeizeShareMantissa method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("protocolSeizeShareMantissa")

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


class ReserveFactorMantissaMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the reserveFactorMantissa method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("reserveFactorMantissa")

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


class SeizeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the seize method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("seize")

    def validate_and_normalize_inputs(self, liquidator: str, borrower: str, seize_tokens: int) -> any:
        """Validate the inputs to the seize method."""
        self.validator.assert_valid(
            method_name='seize',
            parameter_name='liquidator',
            argument_value=liquidator,
        )
        liquidator = self.validate_and_checksum_address(liquidator)
        self.validator.assert_valid(
            method_name='seize',
            parameter_name='borrower',
            argument_value=borrower,
        )
        borrower = self.validate_and_checksum_address(borrower)
        self.validator.assert_valid(
            method_name='seize',
            parameter_name='seizeTokens',
            argument_value=seize_tokens,
        )
        # safeguard against fractional inputs
        seize_tokens = int(seize_tokens)
        return (liquidator, borrower, seize_tokens)

    def block_send(self, liquidator: str, borrower: str, seize_tokens: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(liquidator, borrower, seize_tokens)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: seize")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, liquidator: str, borrower: str, seize_tokens: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (liquidator, borrower, seize_tokens) = self.validate_and_normalize_inputs(liquidator, borrower, seize_tokens)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(liquidator, borrower, seize_tokens).transact(tx_params.as_dict())

    def build_transaction(self, liquidator: str, borrower: str, seize_tokens: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (liquidator, borrower, seize_tokens) = self.validate_and_normalize_inputs(liquidator, borrower, seize_tokens)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(liquidator, borrower, seize_tokens).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, liquidator: str, borrower: str, seize_tokens: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (liquidator, borrower, seize_tokens) = self.validate_and_normalize_inputs(liquidator, borrower, seize_tokens)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(liquidator, borrower, seize_tokens).estimateGas(tx_params.as_dict())


class SupplyRatePerBlockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the supplyRatePerBlock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("supplyRatePerBlock")

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


class TotalBorrowsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the totalBorrows method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("totalBorrows")

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


class TotalBorrowsCurrentMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the totalBorrowsCurrent method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("totalBorrowsCurrent")

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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: total_borrows_current")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

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


class TotalReservesMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the totalReserves method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("totalReserves")

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

    def validate_and_normalize_inputs(self, dst: str, amount: int) -> any:
        """Validate the inputs to the transfer method."""
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='dst',
            argument_value=dst,
        )
        dst = self.validate_and_checksum_address(dst)
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (dst, amount)

    def block_send(self, dst: str, amount: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(dst, amount)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (dst, amount) = self.validate_and_normalize_inputs(dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, amount).transact(tx_params.as_dict())

    def build_transaction(self, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (dst, amount) = self.validate_and_normalize_inputs(dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (dst, amount) = self.validate_and_normalize_inputs(dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(dst, amount).estimateGas(tx_params.as_dict())


class TransferFromMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transferFrom method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("transferFrom")

    def validate_and_normalize_inputs(self, src: str, dst: str, amount: int) -> any:
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
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (src, dst, amount)

    def block_send(self, src: str, dst: str, amount: int, _gaswei: int, _pricewei: int, _valeth: int = 0, _debugtx: bool = False, _receipList: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(src, dst, amount)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: transfer_from")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, src: str, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (src, dst, amount) = self.validate_and_normalize_inputs(src, dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, amount).transact(tx_params.as_dict())

    def build_transaction(self, src: str, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (src, dst, amount) = self.validate_and_normalize_inputs(src, dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, src: str, dst: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (src, dst, amount) = self.validate_and_normalize_inputs(src, dst, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(src, dst, amount).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def accept_admin_(self) -> str:
        return self._function_signatures["_acceptAdmin"]

    def reduce_reserves_(self) -> str:
        return self._function_signatures["_reduceReserves"]

    def set_comptroller_(self) -> str:
        return self._function_signatures["_setComptroller"]

    def set_interest_rate_model_(self) -> str:
        return self._function_signatures["_setInterestRateModel"]

    def set_pending_admin_(self) -> str:
        return self._function_signatures["_setPendingAdmin"]

    def set_reserve_factor_(self) -> str:
        return self._function_signatures["_setReserveFactor"]

    def accrual_block_number(self) -> str:
        return self._function_signatures["accrualBlockNumber"]

    def accrue_interest(self) -> str:
        return self._function_signatures["accrueInterest"]

    def admin(self) -> str:
        return self._function_signatures["admin"]

    def allowance(self) -> str:
        return self._function_signatures["allowance"]

    def approve(self) -> str:
        return self._function_signatures["approve"]

    def balance_of(self) -> str:
        return self._function_signatures["balanceOf"]

    def balance_of_underlying(self) -> str:
        return self._function_signatures["balanceOfUnderlying"]

    def borrow_balance_current(self) -> str:
        return self._function_signatures["borrowBalanceCurrent"]

    def borrow_balance_stored(self) -> str:
        return self._function_signatures["borrowBalanceStored"]

    def borrow_index(self) -> str:
        return self._function_signatures["borrowIndex"]

    def borrow_rate_per_block(self) -> str:
        return self._function_signatures["borrowRatePerBlock"]

    def comptroller(self) -> str:
        return self._function_signatures["comptroller"]

    def decimals(self) -> str:
        return self._function_signatures["decimals"]

    def exchange_rate_current(self) -> str:
        return self._function_signatures["exchangeRateCurrent"]

    def exchange_rate_stored(self) -> str:
        return self._function_signatures["exchangeRateStored"]

    def get_account_snapshot(self) -> str:
        return self._function_signatures["getAccountSnapshot"]

    def get_cash(self) -> str:
        return self._function_signatures["getCash"]

    def initialize(self) -> str:
        return self._function_signatures["initialize"]

    def interest_rate_model(self) -> str:
        return self._function_signatures["interestRateModel"]

    def is_c_token(self) -> str:
        return self._function_signatures["isCToken"]

    def name(self) -> str:
        return self._function_signatures["name"]

    def pending_admin(self) -> str:
        return self._function_signatures["pendingAdmin"]

    def protocol_seize_share_mantissa(self) -> str:
        return self._function_signatures["protocolSeizeShareMantissa"]

    def reserve_factor_mantissa(self) -> str:
        return self._function_signatures["reserveFactorMantissa"]

    def seize(self) -> str:
        return self._function_signatures["seize"]

    def supply_rate_per_block(self) -> str:
        return self._function_signatures["supplyRatePerBlock"]

    def symbol(self) -> str:
        return self._function_signatures["symbol"]

    def total_borrows(self) -> str:
        return self._function_signatures["totalBorrows"]

    def total_borrows_current(self) -> str:
        return self._function_signatures["totalBorrowsCurrent"]

    def total_reserves(self) -> str:
        return self._function_signatures["totalReserves"]

    def total_supply(self) -> str:
        return self._function_signatures["totalSupply"]

    def transfer(self) -> str:
        return self._function_signatures["transfer"]

    def transfer_from(self) -> str:
        return self._function_signatures["transferFrom"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class CToken(ContractBase):
    """Wrapper class for CToken Solidity contract."""
    _fn_accept_admin_: AcceptAdmin_Method
    """Constructor-initialized instance of
    :class:`AcceptAdmin_Method`.
    """

    _fn_reduce_reserves_: ReduceReserves_Method
    """Constructor-initialized instance of
    :class:`ReduceReserves_Method`.
    """

    _fn_set_comptroller_: SetComptroller_Method
    """Constructor-initialized instance of
    :class:`SetComptroller_Method`.
    """

    _fn_set_interest_rate_model_: SetInterestRateModel_Method
    """Constructor-initialized instance of
    :class:`SetInterestRateModel_Method`.
    """

    _fn_set_pending_admin_: SetPendingAdmin_Method
    """Constructor-initialized instance of
    :class:`SetPendingAdmin_Method`.
    """

    _fn_set_reserve_factor_: SetReserveFactor_Method
    """Constructor-initialized instance of
    :class:`SetReserveFactor_Method`.
    """

    _fn_accrual_block_number: AccrualBlockNumberMethod
    """Constructor-initialized instance of
    :class:`AccrualBlockNumberMethod`.
    """

    _fn_accrue_interest: AccrueInterestMethod
    """Constructor-initialized instance of
    :class:`AccrueInterestMethod`.
    """

    _fn_admin: AdminMethod
    """Constructor-initialized instance of
    :class:`AdminMethod`.
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

    _fn_balance_of_underlying: BalanceOfUnderlyingMethod
    """Constructor-initialized instance of
    :class:`BalanceOfUnderlyingMethod`.
    """

    _fn_borrow_balance_current: BorrowBalanceCurrentMethod
    """Constructor-initialized instance of
    :class:`BorrowBalanceCurrentMethod`.
    """

    _fn_borrow_balance_stored: BorrowBalanceStoredMethod
    """Constructor-initialized instance of
    :class:`BorrowBalanceStoredMethod`.
    """

    _fn_borrow_index: BorrowIndexMethod
    """Constructor-initialized instance of
    :class:`BorrowIndexMethod`.
    """

    _fn_borrow_rate_per_block: BorrowRatePerBlockMethod
    """Constructor-initialized instance of
    :class:`BorrowRatePerBlockMethod`.
    """

    _fn_comptroller: ComptrollerMethod
    """Constructor-initialized instance of
    :class:`ComptrollerMethod`.
    """

    _fn_decimals: DecimalsMethod
    """Constructor-initialized instance of
    :class:`DecimalsMethod`.
    """

    _fn_exchange_rate_current: ExchangeRateCurrentMethod
    """Constructor-initialized instance of
    :class:`ExchangeRateCurrentMethod`.
    """

    _fn_exchange_rate_stored: ExchangeRateStoredMethod
    """Constructor-initialized instance of
    :class:`ExchangeRateStoredMethod`.
    """

    _fn_get_account_snapshot: GetAccountSnapshotMethod
    """Constructor-initialized instance of
    :class:`GetAccountSnapshotMethod`.
    """

    _fn_get_cash: GetCashMethod
    """Constructor-initialized instance of
    :class:`GetCashMethod`.
    """

    _fn_initialize: InitializeMethod
    """Constructor-initialized instance of
    :class:`InitializeMethod`.
    """

    _fn_interest_rate_model: InterestRateModelMethod
    """Constructor-initialized instance of
    :class:`InterestRateModelMethod`.
    """

    _fn_is_c_token: IsCTokenMethod
    """Constructor-initialized instance of
    :class:`IsCTokenMethod`.
    """

    _fn_name: NameMethod
    """Constructor-initialized instance of
    :class:`NameMethod`.
    """

    _fn_pending_admin: PendingAdminMethod
    """Constructor-initialized instance of
    :class:`PendingAdminMethod`.
    """

    _fn_protocol_seize_share_mantissa: ProtocolSeizeShareMantissaMethod
    """Constructor-initialized instance of
    :class:`ProtocolSeizeShareMantissaMethod`.
    """

    _fn_reserve_factor_mantissa: ReserveFactorMantissaMethod
    """Constructor-initialized instance of
    :class:`ReserveFactorMantissaMethod`.
    """

    _fn_seize: SeizeMethod
    """Constructor-initialized instance of
    :class:`SeizeMethod`.
    """

    _fn_supply_rate_per_block: SupplyRatePerBlockMethod
    """Constructor-initialized instance of
    :class:`SupplyRatePerBlockMethod`.
    """

    _fn_symbol: SymbolMethod
    """Constructor-initialized instance of
    :class:`SymbolMethod`.
    """

    _fn_total_borrows: TotalBorrowsMethod
    """Constructor-initialized instance of
    :class:`TotalBorrowsMethod`.
    """

    _fn_total_borrows_current: TotalBorrowsCurrentMethod
    """Constructor-initialized instance of
    :class:`TotalBorrowsCurrentMethod`.
    """

    _fn_total_reserves: TotalReservesMethod
    """Constructor-initialized instance of
    :class:`TotalReservesMethod`.
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
            validator: CTokenValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = CTokenValidator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=CToken.abi()).functions
        signed = SignatureGenerator(CToken.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_accept_admin_ = AcceptAdmin_Method(core_lib, contract_address, functions._acceptAdmin, validator)
        self._fn_reduce_reserves_ = ReduceReserves_Method(core_lib, contract_address, functions._reduceReserves, validator)
        self._fn_set_comptroller_ = SetComptroller_Method(core_lib, contract_address, functions._setComptroller, validator)
        self._fn_set_interest_rate_model_ = SetInterestRateModel_Method(core_lib, contract_address, functions._setInterestRateModel, validator)
        self._fn_set_pending_admin_ = SetPendingAdmin_Method(core_lib, contract_address, functions._setPendingAdmin, validator)
        self._fn_set_reserve_factor_ = SetReserveFactor_Method(core_lib, contract_address, functions._setReserveFactor, validator)
        self._fn_accrual_block_number = AccrualBlockNumberMethod(core_lib, contract_address, functions.accrualBlockNumber, validator)
        self._fn_accrue_interest = AccrueInterestMethod(core_lib, contract_address, functions.accrueInterest, validator)
        self._fn_admin = AdminMethod(core_lib, contract_address, functions.admin, validator)
        self._fn_allowance = AllowanceMethod(core_lib, contract_address, functions.allowance, validator)
        self._fn_approve = ApproveMethod(core_lib, contract_address, functions.approve, validator)
        self._fn_balance_of = BalanceOfMethod(core_lib, contract_address, functions.balanceOf, validator)
        self._fn_balance_of_underlying = BalanceOfUnderlyingMethod(core_lib, contract_address, functions.balanceOfUnderlying, validator)
        self._fn_borrow_balance_current = BorrowBalanceCurrentMethod(core_lib, contract_address, functions.borrowBalanceCurrent, validator)
        self._fn_borrow_balance_stored = BorrowBalanceStoredMethod(core_lib, contract_address, functions.borrowBalanceStored, validator)
        self._fn_borrow_index = BorrowIndexMethod(core_lib, contract_address, functions.borrowIndex, validator)
        self._fn_borrow_rate_per_block = BorrowRatePerBlockMethod(core_lib, contract_address, functions.borrowRatePerBlock, validator)
        self._fn_comptroller = ComptrollerMethod(core_lib, contract_address, functions.comptroller, validator)
        self._fn_decimals = DecimalsMethod(core_lib, contract_address, functions.decimals, validator)
        self._fn_exchange_rate_current = ExchangeRateCurrentMethod(core_lib, contract_address, functions.exchangeRateCurrent, validator)
        self._fn_exchange_rate_stored = ExchangeRateStoredMethod(core_lib, contract_address, functions.exchangeRateStored, validator)
        self._fn_get_account_snapshot = GetAccountSnapshotMethod(core_lib, contract_address, functions.getAccountSnapshot, validator)
        self._fn_get_cash = GetCashMethod(core_lib, contract_address, functions.getCash, validator)
        self._fn_initialize = InitializeMethod(core_lib, contract_address, functions.initialize, validator)
        self._fn_interest_rate_model = InterestRateModelMethod(core_lib, contract_address, functions.interestRateModel, validator)
        self._fn_is_c_token = IsCTokenMethod(core_lib, contract_address, functions.isCToken, validator)
        self._fn_name = NameMethod(core_lib, contract_address, functions.name, validator)
        self._fn_pending_admin = PendingAdminMethod(core_lib, contract_address, functions.pendingAdmin, validator)
        self._fn_protocol_seize_share_mantissa = ProtocolSeizeShareMantissaMethod(core_lib, contract_address, functions.protocolSeizeShareMantissa, validator)
        self._fn_reserve_factor_mantissa = ReserveFactorMantissaMethod(core_lib, contract_address, functions.reserveFactorMantissa, validator)
        self._fn_seize = SeizeMethod(core_lib, contract_address, functions.seize, validator)
        self._fn_supply_rate_per_block = SupplyRatePerBlockMethod(core_lib, contract_address, functions.supplyRatePerBlock, validator)
        self._fn_symbol = SymbolMethod(core_lib, contract_address, functions.symbol, validator)
        self._fn_total_borrows = TotalBorrowsMethod(core_lib, contract_address, functions.totalBorrows, validator)
        self._fn_total_borrows_current = TotalBorrowsCurrentMethod(core_lib, contract_address, functions.totalBorrowsCurrent, validator)
        self._fn_total_reserves = TotalReservesMethod(core_lib, contract_address, functions.totalReserves, validator)
        self._fn_total_supply = TotalSupplyMethod(core_lib, contract_address, functions.totalSupply, validator)
        self._fn_transfer = TransferMethod(core_lib, contract_address, functions.transfer, validator)
        self._fn_transfer_from = TransferFromMethod(core_lib, contract_address, functions.transferFrom, validator)

    def event_accrue_interest(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event accrue_interest in contract CToken
        Get log entry for AccrueInterest event.
                :param tx_hash: hash of transaction emitting AccrueInterest event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.AccrueInterest().processReceipt(tx_receipt)

    def event_approval(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event approval in contract CToken
        Get log entry for Approval event.
                :param tx_hash: hash of transaction emitting Approval event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Approval().processReceipt(tx_receipt)

    def event_borrow(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event borrow in contract CToken
        Get log entry for Borrow event.
                :param tx_hash: hash of transaction emitting Borrow event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Borrow().processReceipt(tx_receipt)

    def event_failure(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event failure in contract CToken
        Get log entry for Failure event.
                :param tx_hash: hash of transaction emitting Failure event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Failure().processReceipt(tx_receipt)

    def event_liquidate_borrow(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event liquidate_borrow in contract CToken
        Get log entry for LiquidateBorrow event.
                :param tx_hash: hash of transaction emitting LiquidateBorrow event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.LiquidateBorrow().processReceipt(tx_receipt)

    def event_mint(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event mint in contract CToken
        Get log entry for Mint event.
                :param tx_hash: hash of transaction emitting Mint event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Mint().processReceipt(tx_receipt)

    def event_new_admin(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_admin in contract CToken
        Get log entry for NewAdmin event.
                :param tx_hash: hash of transaction emitting NewAdmin event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.NewAdmin().processReceipt(tx_receipt)

    def event_new_comptroller(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_comptroller in contract CToken
        Get log entry for NewComptroller event.
                :param tx_hash: hash of transaction emitting NewComptroller event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.NewComptroller().processReceipt(tx_receipt)

    def event_new_market_interest_rate_model(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_market_interest_rate_model in contract CToken
        Get log entry for NewMarketInterestRateModel event.
                :param tx_hash: hash of transaction emitting NewMarketInterestRateModel
                event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.NewMarketInterestRateModel().processReceipt(tx_receipt)

    def event_new_pending_admin(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_pending_admin in contract CToken
        Get log entry for NewPendingAdmin event.
                :param tx_hash: hash of transaction emitting NewPendingAdmin event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.NewPendingAdmin().processReceipt(tx_receipt)

    def event_new_reserve_factor(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_reserve_factor in contract CToken
        Get log entry for NewReserveFactor event.
                :param tx_hash: hash of transaction emitting NewReserveFactor event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.NewReserveFactor().processReceipt(tx_receipt)

    def event_redeem(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event redeem in contract CToken
        Get log entry for Redeem event.
                :param tx_hash: hash of transaction emitting Redeem event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Redeem().processReceipt(tx_receipt)

    def event_repay_borrow(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event repay_borrow in contract CToken
        Get log entry for RepayBorrow event.
                :param tx_hash: hash of transaction emitting RepayBorrow event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.RepayBorrow().processReceipt(tx_receipt)

    def event_reserves_added(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event reserves_added in contract CToken
        Get log entry for ReservesAdded event.
                :param tx_hash: hash of transaction emitting ReservesAdded event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.ReservesAdded().processReceipt(tx_receipt)

    def event_reserves_reduced(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event reserves_reduced in contract CToken
        Get log entry for ReservesReduced event.
                :param tx_hash: hash of transaction emitting ReservesReduced event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.ReservesReduced().processReceipt(tx_receipt)

    def event_transfer(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event transfer in contract CToken
        Get log entry for Transfer event.
                :param tx_hash: hash of transaction emitting Transfer event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=CToken.abi()).events.Transfer().processReceipt(tx_receipt)

    def accept_admin_(self) -> int:
        """
        Implementation of accept_admin_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_accept_admin_.block_send(self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def reduce_reserves_(self, reduce_amount: int) -> int:
        """
        Implementation of reduce_reserves_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_reduce_reserves_.block_send(reduce_amount, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_comptroller_(self, new_comptroller: str) -> int:
        """
        Implementation of set_comptroller_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_set_comptroller_.block_send(new_comptroller, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_interest_rate_model_(self, new_interest_rate_model: str) -> int:
        """
        Implementation of set_interest_rate_model_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_set_interest_rate_model_.block_send(new_interest_rate_model, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_pending_admin_(self, new_pending_admin: str) -> int:
        """
        Implementation of set_pending_admin_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_set_pending_admin_.block_send(new_pending_admin, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_reserve_factor_(self, new_reserve_factor_mantissa: int) -> int:
        """
        Implementation of set_reserve_factor_ in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_set_reserve_factor_.block_send(new_reserve_factor_mantissa, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def accrual_block_number(self) -> int:
        """
        Implementation of accrual_block_number in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_accrual_block_number.block_call()

    def accrue_interest(self) -> int:
        """
        Implementation of accrue_interest in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_accrue_interest.block_send(self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def admin(self) -> str:
        """
        Implementation of admin in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_admin.block_call()

    def allowance(self, owner: str, spender: str) -> int:
        """
        Implementation of allowance in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_allowance.block_call(owner, spender)

    def approve(self, spender: str, amount: int) -> bool:
        """
        Implementation of approve in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_approve.block_send(spender, amount, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def balance_of(self, owner: str) -> int:
        """
        Implementation of balance_of in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_balance_of.block_call(owner)

    def balance_of_underlying(self, owner: str) -> int:
        """
        Implementation of balance_of_underlying in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_balance_of_underlying.block_send(owner, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def borrow_balance_current(self, account: str) -> int:
        """
        Implementation of borrow_balance_current in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_borrow_balance_current.block_send(account, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def borrow_balance_stored(self, account: str) -> int:
        """
        Implementation of borrow_balance_stored in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_borrow_balance_stored.block_call(account)

    def borrow_index(self) -> int:
        """
        Implementation of borrow_index in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_borrow_index.block_call()

    def borrow_rate_per_block(self) -> int:
        """
        Implementation of borrow_rate_per_block in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_borrow_rate_per_block.block_call()

    def comptroller(self) -> str:
        """
        Implementation of comptroller in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_comptroller.block_call()

    def decimals(self) -> int:
        """
        Implementation of decimals in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_decimals.block_call()

    def exchange_rate_current(self) -> int:
        """
        Implementation of exchange_rate_current in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_exchange_rate_current.block_send(self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def exchange_rate_stored(self) -> int:
        """
        Implementation of exchange_rate_stored in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_exchange_rate_stored.block_call()

    def get_account_snapshot(self, account: str) -> Tuple[int, int, int, int]:
        """
        Implementation of get_account_snapshot in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_get_account_snapshot.block_call(account)

    def get_cash(self) -> int:
        """
        Implementation of get_cash in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_get_cash.block_call()

    def initialize(self, comptroller_: str, interest_rate_model_: str, initial_exchange_rate_mantissa_: int, name_: str, symbol_: str, decimals_: int) -> None:
        """
        Implementation of initialize in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_initialize.block_send(comptroller_, interest_rate_model_, initial_exchange_rate_mantissa_, name_, symbol_, decimals_, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def interest_rate_model(self) -> str:
        """
        Implementation of interest_rate_model in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_interest_rate_model.block_call()

    def is_c_token(self) -> bool:
        """
        Implementation of is_c_token in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_is_c_token.block_call()

    def name(self) -> str:
        """
        Implementation of name in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_name.block_call()

    def pending_admin(self) -> str:
        """
        Implementation of pending_admin in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_pending_admin.block_call()

    def protocol_seize_share_mantissa(self) -> int:
        """
        Implementation of protocol_seize_share_mantissa in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_protocol_seize_share_mantissa.block_call()

    def reserve_factor_mantissa(self) -> int:
        """
        Implementation of reserve_factor_mantissa in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_reserve_factor_mantissa.block_call()

    def seize(self, liquidator: str, borrower: str, seize_tokens: int) -> int:
        """
        Implementation of seize in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_seize.block_send(liquidator, borrower, seize_tokens, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def supply_rate_per_block(self) -> int:
        """
        Implementation of supply_rate_per_block in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_supply_rate_per_block.block_call()

    def symbol(self) -> str:
        """
        Implementation of symbol in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_symbol.block_call()

    def total_borrows(self) -> int:
        """
        Implementation of total_borrows in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_total_borrows.block_call()

    def total_borrows_current(self) -> int:
        """
        Implementation of total_borrows_current in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_total_borrows_current.block_send(self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def total_reserves(self) -> int:
        """
        Implementation of total_reserves in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_total_reserves.block_call()

    def total_supply(self) -> int:
        """
        Implementation of total_supply in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_total_supply.block_call()

    def transfer(self, dst: str, amount: int) -> bool:
        """
        Implementation of transfer in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_transfer.block_send(dst, amount, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def transfer_from(self, src: str, dst: str, amount: int) -> bool:
        """
        Implementation of transfer_from in contract CToken
        Method of the function
    
    
    
        """

        return self._fn_transfer_from.block_send(src, dst, amount, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def CallContractWait(self, t_long: int) -> "CToken":
        self._fn_accept_admin_.setWait(t_long)
        self._fn_reduce_reserves_.setWait(t_long)
        self._fn_set_comptroller_.setWait(t_long)
        self._fn_set_interest_rate_model_.setWait(t_long)
        self._fn_set_pending_admin_.setWait(t_long)
        self._fn_set_reserve_factor_.setWait(t_long)
        self._fn_accrual_block_number.setWait(t_long)
        self._fn_accrue_interest.setWait(t_long)
        self._fn_admin.setWait(t_long)
        self._fn_allowance.setWait(t_long)
        self._fn_approve.setWait(t_long)
        self._fn_balance_of.setWait(t_long)
        self._fn_balance_of_underlying.setWait(t_long)
        self._fn_borrow_balance_current.setWait(t_long)
        self._fn_borrow_balance_stored.setWait(t_long)
        self._fn_borrow_index.setWait(t_long)
        self._fn_borrow_rate_per_block.setWait(t_long)
        self._fn_comptroller.setWait(t_long)
        self._fn_decimals.setWait(t_long)
        self._fn_exchange_rate_current.setWait(t_long)
        self._fn_exchange_rate_stored.setWait(t_long)
        self._fn_get_account_snapshot.setWait(t_long)
        self._fn_get_cash.setWait(t_long)
        self._fn_initialize.setWait(t_long)
        self._fn_interest_rate_model.setWait(t_long)
        self._fn_is_c_token.setWait(t_long)
        self._fn_name.setWait(t_long)
        self._fn_pending_admin.setWait(t_long)
        self._fn_protocol_seize_share_mantissa.setWait(t_long)
        self._fn_reserve_factor_mantissa.setWait(t_long)
        self._fn_seize.setWait(t_long)
        self._fn_supply_rate_per_block.setWait(t_long)
        self._fn_symbol.setWait(t_long)
        self._fn_total_borrows.setWait(t_long)
        self._fn_total_borrows_current.setWait(t_long)
        self._fn_total_reserves.setWait(t_long)
        self._fn_total_supply.setWait(t_long)
        self._fn_transfer.setWait(t_long)
        self._fn_transfer_from.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"cashPrior","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"interestAccumulated","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"borrowIndex","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"totalBorrows","type":"uint256"}],"name":"AccrueInterest","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"borrower","type":"address"},{"indexed":false,"internalType":"uint256","name":"borrowAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"accountBorrows","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"totalBorrows","type":"uint256"}],"name":"Borrow","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"error","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"info","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"detail","type":"uint256"}],"name":"Failure","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"liquidator","type":"address"},{"indexed":false,"internalType":"address","name":"borrower","type":"address"},{"indexed":false,"internalType":"uint256","name":"repayAmount","type":"uint256"},{"indexed":false,"internalType":"address","name":"cTokenCollateral","type":"address"},{"indexed":false,"internalType":"uint256","name":"seizeTokens","type":"uint256"}],"name":"LiquidateBorrow","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"minter","type":"address"},{"indexed":false,"internalType":"uint256","name":"mintAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"mintTokens","type":"uint256"}],"name":"Mint","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"oldAdmin","type":"address"},{"indexed":false,"internalType":"address","name":"newAdmin","type":"address"}],"name":"NewAdmin","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"contract ComptrollerInterface","name":"oldComptroller","type":"address"},{"indexed":false,"internalType":"contract ComptrollerInterface","name":"newComptroller","type":"address"}],"name":"NewComptroller","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"contract InterestRateModel","name":"oldInterestRateModel","type":"address"},{"indexed":false,"internalType":"contract InterestRateModel","name":"newInterestRateModel","type":"address"}],"name":"NewMarketInterestRateModel","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"oldPendingAdmin","type":"address"},{"indexed":false,"internalType":"address","name":"newPendingAdmin","type":"address"}],"name":"NewPendingAdmin","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"oldReserveFactorMantissa","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newReserveFactorMantissa","type":"uint256"}],"name":"NewReserveFactor","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"redeemer","type":"address"},{"indexed":false,"internalType":"uint256","name":"redeemAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"redeemTokens","type":"uint256"}],"name":"Redeem","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"payer","type":"address"},{"indexed":false,"internalType":"address","name":"borrower","type":"address"},{"indexed":false,"internalType":"uint256","name":"repayAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"accountBorrows","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"totalBorrows","type":"uint256"}],"name":"RepayBorrow","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"benefactor","type":"address"},{"indexed":false,"internalType":"uint256","name":"addAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newTotalReserves","type":"uint256"}],"name":"ReservesAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"admin","type":"address"},{"indexed":false,"internalType":"uint256","name":"reduceAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newTotalReserves","type":"uint256"}],"name":"ReservesReduced","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":false,"inputs":[],"name":"_acceptAdmin","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"reduceAmount","type":"uint256"}],"name":"_reduceReserves","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"contract ComptrollerInterface","name":"newComptroller","type":"address"}],"name":"_setComptroller","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"contract InterestRateModel","name":"newInterestRateModel","type":"address"}],"name":"_setInterestRateModel","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address payable","name":"newPendingAdmin","type":"address"}],"name":"_setPendingAdmin","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"newReserveFactorMantissa","type":"uint256"}],"name":"_setReserveFactor","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"accrualBlockNumber","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"accrueInterest","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"admin","outputs":[{"internalType":"address payable","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"balanceOfUnderlying","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"borrowBalanceCurrent","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"borrowBalanceStored","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"borrowIndex","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"borrowRatePerBlock","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"comptroller","outputs":[{"internalType":"contract ComptrollerInterface","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"exchangeRateCurrent","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"exchangeRateStored","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"getAccountSnapshot","outputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCash","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"contract ComptrollerInterface","name":"comptroller_","type":"address"},{"internalType":"contract InterestRateModel","name":"interestRateModel_","type":"address"},{"internalType":"uint256","name":"initialExchangeRateMantissa_","type":"uint256"},{"internalType":"string","name":"name_","type":"string"},{"internalType":"string","name":"symbol_","type":"string"},{"internalType":"uint8","name":"decimals_","type":"uint8"}],"name":"initialize","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"interestRateModel","outputs":[{"internalType":"contract InterestRateModel","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"isCToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"pendingAdmin","outputs":[{"internalType":"address payable","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"protocolSeizeShareMantissa","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"reserveFactorMantissa","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"liquidator","type":"address"},{"internalType":"address","name":"borrower","type":"address"},{"internalType":"uint256","name":"seizeTokens","type":"uint256"}],"name":"seize","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"supplyRatePerBlock","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalBorrows","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"totalBorrowsCurrent","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalReserves","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"src","type":"address"},{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
