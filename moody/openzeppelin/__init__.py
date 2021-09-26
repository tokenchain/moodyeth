"""Generated wrapper for Timelock6h Solidity contract."""

# pylint: disable=too-many-arguments

import json
import time
from typing import (  # pylint: disable=unused-import
    Optional,
    Tuple,
    Union,
)

from eth_utils import to_checksum_address
from hexbytes import HexBytes
from web3.contract import ContractFunction
from web3.datastructures import AttributeDict
from web3.exceptions import ContractLogicError

from moody import Bolors
from moody.libeb import MiliDoS
from moody.m.bases import ContractMethod, Validator, ContractBase
from moody.m.tx_params import TxParams

# Try to import a custom validator class definition; if there isn't one,
# declare one that we can instantiate for the default argument to the
# constructor for Timelock6h below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        Timelock6hValidator,
    )
except ImportError:

    class Timelock6hValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class GracePeriodMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the GRACE_PERIOD method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class MaximumDelayMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the MAXIMUM_DELAY method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class MinimumDelayMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the MINIMUM_DELAY method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class AcceptAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the acceptAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_send(self, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method()
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -accept_admin")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: accept_admin")

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

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class CancelTransactionMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the cancelTransaction method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int) -> any:
        """Validate the inputs to the cancelTransaction method."""
        self.validator.assert_valid(
            method_name='cancelTransaction',
            parameter_name='target',
            argument_value=target,
        )
        target = self.validate_and_checksum_address(target)
        self.validator.assert_valid(
            method_name='cancelTransaction',
            parameter_name='value',
            argument_value=value,
        )
        # safeguard against fractional inputs
        value = int(value)
        self.validator.assert_valid(
            method_name='cancelTransaction',
            parameter_name='signature',
            argument_value=signature,
        )
        self.validator.assert_valid(
            method_name='cancelTransaction',
            parameter_name='data',
            argument_value=data,
        )
        self.validator.assert_valid(
            method_name='cancelTransaction',
            parameter_name='eta',
            argument_value=eta,
        )
        # safeguard against fractional inputs
        eta = int(eta)
        return (target, value, signature, data, eta)

    def block_send(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(target, value, signature, data, eta)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -cancel_transaction")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: cancel_transaction")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).transact(tx_params.as_dict())

    def build_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).estimateGas(tx_params.as_dict())


class DelayMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the delay method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class ExecuteTransactionMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the executeTransaction method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int) -> any:
        """Validate the inputs to the executeTransaction method."""
        self.validator.assert_valid(
            method_name='executeTransaction',
            parameter_name='target',
            argument_value=target,
        )
        target = self.validate_and_checksum_address(target)
        self.validator.assert_valid(
            method_name='executeTransaction',
            parameter_name='value',
            argument_value=value,
        )
        # safeguard against fractional inputs
        value = int(value)
        self.validator.assert_valid(
            method_name='executeTransaction',
            parameter_name='signature',
            argument_value=signature,
        )
        self.validator.assert_valid(
            method_name='executeTransaction',
            parameter_name='data',
            argument_value=data,
        )
        self.validator.assert_valid(
            method_name='executeTransaction',
            parameter_name='eta',
            argument_value=eta,
        )
        # safeguard against fractional inputs
        eta = int(eta)
        return (target, value, signature, data, eta)

    def block_send(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(target, value, signature, data, eta)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -execute_transaction")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: execute_transaction")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).transact(tx_params.as_dict())

    def build_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).estimateGas(tx_params.as_dict())


class PendingAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the pendingAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

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


class QueueTransactionMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the queueTransaction method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int) -> any:
        """Validate the inputs to the queueTransaction method."""
        self.validator.assert_valid(
            method_name='queueTransaction',
            parameter_name='target',
            argument_value=target,
        )
        target = self.validate_and_checksum_address(target)
        self.validator.assert_valid(
            method_name='queueTransaction',
            parameter_name='value',
            argument_value=value,
        )
        # safeguard against fractional inputs
        value = int(value)
        self.validator.assert_valid(
            method_name='queueTransaction',
            parameter_name='signature',
            argument_value=signature,
        )
        self.validator.assert_valid(
            method_name='queueTransaction',
            parameter_name='data',
            argument_value=data,
        )
        self.validator.assert_valid(
            method_name='queueTransaction',
            parameter_name='eta',
            argument_value=eta,
        )
        # safeguard against fractional inputs
        eta = int(eta)
        return (target, value, signature, data, eta)

    def block_send(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(target, value, signature, data, eta)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -queue_transaction")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: queue_transaction")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).transact(tx_params.as_dict())

    def build_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (target, value, signature, data, eta) = self.validate_and_normalize_inputs(target, value, signature, data, eta)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(target, value, signature, data, eta).estimateGas(tx_params.as_dict())


class QueuedTransactionsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the queuedTransactions method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, index_0: Union[bytes, str]) -> any:
        """Validate the inputs to the queuedTransactions method."""
        self.validator.assert_valid(
            method_name='queuedTransactions',
            parameter_name='index_0',
            argument_value=index_0,
        )
        return (index_0)

    def block_call(self, index_0: Union[bytes, str], debug: bool = False) -> bool:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, index_0: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())


class SetDelayMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setDelay method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, delay_: int) -> any:
        """Validate the inputs to the setDelay method."""
        self.validator.assert_valid(
            method_name='setDelay',
            parameter_name='delay_',
            argument_value=delay_,
        )
        # safeguard against fractional inputs
        delay_ = int(delay_)
        return (delay_)

    def block_send(self, delay_: int, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(delay_)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -set_delay")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_delay")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, delay_: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (delay_) = self.validate_and_normalize_inputs(delay_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delay_).transact(tx_params.as_dict())

    def build_transaction(self, delay_: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (delay_) = self.validate_and_normalize_inputs(delay_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delay_).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, delay_: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (delay_) = self.validate_and_normalize_inputs(delay_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(delay_).estimateGas(tx_params.as_dict())


class SetPendingAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setPendingAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, pending_admin_: str) -> any:
        """Validate the inputs to the setPendingAdmin method."""
        self.validator.assert_valid(
            method_name='setPendingAdmin',
            parameter_name='pendingAdmin_',
            argument_value=pending_admin_,
        )
        pending_admin_ = self.validate_and_checksum_address(pending_admin_)
        return (pending_admin_)

    def block_send(self, pending_admin_: str, gas: int, price: int, val: int = 0, debug: bool = False, receiptListen: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(pending_admin_)
        try:

            _t = _fn.buildTransaction({
                'from': self._operate,
                'gas': gas,
                'gasPrice': price
            })
            _t['nonce'] = self._web3_eth.getTransactionCount(self._operate)

            if val > 0:
                _t['value'] = val

            if debug:
                print(f"======== Signing ✅ by {self._operate}")
                print(f"======== Transaction ✅ check")
                print(_t)

            if 'data' in _t:

                signed = self._web3_eth.account.sign_transaction(_t)
                txHash = self._web3_eth.sendRawTransaction(signed.rawTransaction)
                tx_receipt = None
                if receiptListen is True:
                    print("======== awaiting Confirmation 🚸️ -set_pending_admin")
                    tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                    if debug:
                        print("======== TX Result ✅")
                        print(tx_receipt)

                print(f"======== TX blockHash ✅")
                if receiptListen is True and tx_receipt is not None:
                    print(f"{Bolors.OK}{tx_receipt.blockHash.hex()}{Bolors.RESET}")
                else:
                    print(f"{Bolors.WARNING}{txHash.hex()}{Bolors.RESET}")

            if receiptListen is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_pending_admin")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")

    def send_transaction(self, pending_admin_: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (pending_admin_) = self.validate_and_normalize_inputs(pending_admin_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pending_admin_).transact(tx_params.as_dict())

    def build_transaction(self, pending_admin_: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (pending_admin_) = self.validate_and_normalize_inputs(pending_admin_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pending_admin_).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, pending_admin_: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (pending_admin_) = self.validate_and_normalize_inputs(pending_admin_)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(pending_admin_).estimateGas(tx_params.as_dict())


class SignatureGenerator:
    _function_signatures = {}

    def __init__(self, abi: any):
        for func in [obj for obj in abi if obj['type'] == 'function']:
            name = func['name']
            types = [input['type'] for input in func['inputs']]
            self._function_signatures[name] = '{}({})'.format(name, ','.join(types))

    def grace_period(self) -> str:
        return self._function_signatures["GRACE_PERIOD"]

    def maximum_delay(self) -> str:
        return self._function_signatures["MAXIMUM_DELAY"]

    def minimum_delay(self) -> str:
        return self._function_signatures["MINIMUM_DELAY"]

    def accept_admin(self) -> str:
        return self._function_signatures["acceptAdmin"]

    def admin(self) -> str:
        return self._function_signatures["admin"]

    def cancel_transaction(self) -> str:
        return self._function_signatures["cancelTransaction"]

    def delay(self) -> str:
        return self._function_signatures["delay"]

    def execute_transaction(self) -> str:
        return self._function_signatures["executeTransaction"]

    def pending_admin(self) -> str:
        return self._function_signatures["pendingAdmin"]

    def queue_transaction(self) -> str:
        return self._function_signatures["queueTransaction"]

    def queued_transactions(self) -> str:
        return self._function_signatures["queuedTransactions"]

    def set_delay(self) -> str:
        return self._function_signatures["setDelay"]

    def set_pending_admin(self) -> str:
        return self._function_signatures["setPendingAdmin"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Timelock6h(ContractBase):
    """Wrapper class for Timelock6h Solidity contract.

    All method parameters of type `bytes`:code: should be encoded as UTF-8,
    which can be accomplished via `str.encode("utf_8")`:code:.
    """
    _fn_grace_period: GracePeriodMethod
    """Constructor-initialized instance of
    :class:`GracePeriodMethod`.
    """

    _fn_maximum_delay: MaximumDelayMethod
    """Constructor-initialized instance of
    :class:`MaximumDelayMethod`.
    """

    _fn_minimum_delay: MinimumDelayMethod
    """Constructor-initialized instance of
    :class:`MinimumDelayMethod`.
    """

    _fn_accept_admin: AcceptAdminMethod
    """Constructor-initialized instance of
    :class:`AcceptAdminMethod`.
    """

    _fn_admin: AdminMethod
    """Constructor-initialized instance of
    :class:`AdminMethod`.
    """

    _fn_cancel_transaction: CancelTransactionMethod
    """Constructor-initialized instance of
    :class:`CancelTransactionMethod`.
    """

    _fn_delay: DelayMethod
    """Constructor-initialized instance of
    :class:`DelayMethod`.
    """

    _fn_execute_transaction: ExecuteTransactionMethod
    """Constructor-initialized instance of
    :class:`ExecuteTransactionMethod`.
    """

    _fn_pending_admin: PendingAdminMethod
    """Constructor-initialized instance of
    :class:`PendingAdminMethod`.
    """

    _fn_queue_transaction: QueueTransactionMethod
    """Constructor-initialized instance of
    :class:`QueueTransactionMethod`.
    """

    _fn_queued_transactions: QueuedTransactionsMethod
    """Constructor-initialized instance of
    :class:`QueuedTransactionsMethod`.
    """

    _fn_set_delay: SetDelayMethod
    """Constructor-initialized instance of
    :class:`SetDelayMethod`.
    """

    _fn_set_pending_admin: SetPendingAdminMethod
    """Constructor-initialized instance of
    :class:`SetPendingAdminMethod`.
    """

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: Timelock6hValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = Timelock6hValidator(web3, contract_address)

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

        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Timelock6h.abi()).functions
        self.SIGNATURES = SignatureGenerator(Timelock6h.abi())
        self._fn_grace_period = GracePeriodMethod(core_lib, contract_address, functions.GRACE_PERIOD)

        self._fn_maximum_delay = MaximumDelayMethod(core_lib, contract_address, functions.MAXIMUM_DELAY)

        self._fn_minimum_delay = MinimumDelayMethod(core_lib, contract_address, functions.MINIMUM_DELAY)

        self._fn_accept_admin = AcceptAdminMethod(core_lib, contract_address, functions.acceptAdmin)

        self._fn_admin = AdminMethod(core_lib, contract_address, functions.admin)

        self._fn_cancel_transaction = CancelTransactionMethod(core_lib, contract_address, functions.cancelTransaction, validator)

        self._fn_delay = DelayMethod(core_lib, contract_address, functions.delay)

        self._fn_execute_transaction = ExecuteTransactionMethod(core_lib, contract_address, functions.executeTransaction, validator)

        self._fn_pending_admin = PendingAdminMethod(core_lib, contract_address, functions.pendingAdmin)

        self._fn_queue_transaction = QueueTransactionMethod(core_lib, contract_address, functions.queueTransaction, validator)

        self._fn_queued_transactions = QueuedTransactionsMethod(core_lib, contract_address, functions.queuedTransactions, validator)

        self._fn_set_delay = SetDelayMethod(core_lib, contract_address, functions.setDelay, validator)

        self._fn_set_pending_admin = SetPendingAdminMethod(core_lib, contract_address, functions.setPendingAdmin, validator)

    def event_cancel_transaction(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event cancel_transaction in contract Timelock6h
        Get log entry for CancelTransaction event.
                :param tx_hash: hash of transaction emitting CancelTransaction event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.CancelTransaction().processReceipt(tx_receipt)

    def event_execute_transaction(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event execute_transaction in contract Timelock6h
        Get log entry for ExecuteTransaction event.
                :param tx_hash: hash of transaction emitting ExecuteTransaction event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.ExecuteTransaction().processReceipt(tx_receipt)

    def event_new_admin(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_admin in contract Timelock6h
        Get log entry for NewAdmin event.
                :param tx_hash: hash of transaction emitting NewAdmin event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.NewAdmin().processReceipt(tx_receipt)

    def event_new_delay(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_delay in contract Timelock6h
        Get log entry for NewDelay event.
                :param tx_hash: hash of transaction emitting NewDelay event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.NewDelay().processReceipt(tx_receipt)

    def event_new_pending_admin(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event new_pending_admin in contract Timelock6h
        Get log entry for NewPendingAdmin event.
                :param tx_hash: hash of transaction emitting NewPendingAdmin event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.NewPendingAdmin().processReceipt(tx_receipt)

    def event_queue_transaction(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event queue_transaction in contract Timelock6h
        Get log entry for QueueTransaction event.
                :param tx_hash: hash of transaction emitting QueueTransaction event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Timelock6h.abi()).events.QueueTransaction().processReceipt(tx_receipt)

    def grace_period(self) -> int:
        """
        Implementation of grace_period in contract Timelock6h
        Method of the function



        """

        return self._fn_grace_period.block_call()

    def maximum_delay(self) -> int:
        """
        Implementation of maximum_delay in contract Timelock6h
        Method of the function



        """

        return self._fn_maximum_delay.block_call()

    def minimum_delay(self) -> int:
        """
        Implementation of minimum_delay in contract Timelock6h
        Method of the function



        """

        return self._fn_minimum_delay.block_call()

    def accept_admin(self) -> None:
        """
        Implementation of accept_admin in contract Timelock6h
        Method of the function



        """

        return self._fn_accept_admin.block_send(self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def admin(self) -> str:
        """
        Implementation of admin in contract Timelock6h
        Method of the function



        """

        return self._fn_admin.block_call()

    def cancel_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int) -> None:
        """
        Implementation of cancel_transaction in contract Timelock6h
        Method of the function



        """

        return self._fn_cancel_transaction.block_send(target, value, signature, data, eta, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def delay(self) -> int:
        """
        Implementation of delay in contract Timelock6h
        Method of the function



        """

        return self._fn_delay.block_call()

    def execute_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int, wei: int = 0) -> Union[bytes, str]:
        """
        Implementation of execute_transaction in contract Timelock6h
        Method of the function



        """

        return self._fn_execute_transaction.block_send(target, value, signature, data, eta, self.call_contract_fee_amount, self.call_contract_fee_price, wei, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def pending_admin(self) -> str:
        """
        Implementation of pending_admin in contract Timelock6h
        Method of the function



        """

        return self._fn_pending_admin.block_call()

    def queue_transaction(self, target: str, value: int, signature: str, data: Union[bytes, str], eta: int) -> Union[bytes, str]:
        """
        Implementation of queue_transaction in contract Timelock6h
        Method of the function



        """

        return self._fn_queue_transaction.block_send(target, value, signature, data, eta, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def queued_transactions(self, index_0: Union[bytes, str]) -> bool:
        """
        Implementation of queued_transactions in contract Timelock6h
        Method of the function



        """

        return self._fn_queued_transactions.block_call(index_0)

    def set_delay(self, delay_: int) -> None:
        """
        Implementation of set_delay in contract Timelock6h
        Method of the function



        """

        return self._fn_set_delay.block_send(delay_, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_pending_admin(self, pending_admin_: str) -> None:
        """
        Implementation of set_pending_admin in contract Timelock6h
        Method of the function



        """

        return self._fn_set_pending_admin.block_send(pending_admin_, self.call_contract_fee_amount, self.call_contract_fee_price, 0, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def CallContractWait(self, t_long: int) -> "Timelock6h":
        self._fn_grace_period.setWait(t_long)
        self._fn_maximum_delay.setWait(t_long)
        self._fn_minimum_delay.setWait(t_long)
        self._fn_accept_admin.setWait(t_long)
        self._fn_admin.setWait(t_long)
        self._fn_cancel_transaction.setWait(t_long)
        self._fn_delay.setWait(t_long)
        self._fn_execute_transaction.setWait(t_long)
        self._fn_pending_admin.setWait(t_long)
        self._fn_queue_transaction.setWait(t_long)
        self._fn_queued_transactions.setWait(t_long)
        self._fn_set_delay.setWait(t_long)
        self._fn_set_pending_admin.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"admin_","type":"address"},{"internalType":"uint256","name":"delay_","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"txHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"target","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"},{"indexed":false,"internalType":"string","name":"signature","type":"string"},{"indexed":false,"internalType":"bytes","name":"data","type":"bytes"},{"indexed":false,"internalType":"uint256","name":"eta","type":"uint256"}],"name":"CancelTransaction","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"txHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"target","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"},{"indexed":false,"internalType":"string","name":"signature","type":"string"},{"indexed":false,"internalType":"bytes","name":"data","type":"bytes"},{"indexed":false,"internalType":"uint256","name":"eta","type":"uint256"}],"name":"ExecuteTransaction","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newAdmin","type":"address"}],"name":"NewAdmin","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"newDelay","type":"uint256"}],"name":"NewDelay","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newPendingAdmin","type":"address"}],"name":"NewPendingAdmin","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"txHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"target","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"},{"indexed":false,"internalType":"string","name":"signature","type":"string"},{"indexed":false,"internalType":"bytes","name":"data","type":"bytes"},{"indexed":false,"internalType":"uint256","name":"eta","type":"uint256"}],"name":"QueueTransaction","type":"event"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"constant":true,"inputs":[],"name":"GRACE_PERIOD","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"MAXIMUM_DELAY","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"MINIMUM_DELAY","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"acceptAdmin","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"admin","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"string","name":"signature","type":"string"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"uint256","name":"eta","type":"uint256"}],"name":"cancelTransaction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"delay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"string","name":"signature","type":"string"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"uint256","name":"eta","type":"uint256"}],"name":"executeTransaction","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[],"name":"pendingAdmin","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"string","name":"signature","type":"string"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"uint256","name":"eta","type":"uint256"}],"name":"queueTransaction","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"bytes32","name":"index_0","type":"bytes32"}],"name":"queuedTransactions","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"delay_","type":"uint256"}],"name":"setDelay","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"pendingAdmin_","type":"address"}],"name":"setPendingAdmin","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
