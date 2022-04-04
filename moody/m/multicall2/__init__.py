"""Generated wrapper for Multicall2 Solidity contract."""

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
# constructor for Multicall2 below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        Multicall2Validator,
    )
except ImportError:

    class Multicall2Validator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class Multicall2Call(TypedDict):
    """Python representation of a tuple or struct.

    Solidity compiler output does not include the names of structs that appear
    in method definitions.  A tuple found in an ABI may have been written in
    Solidity as a literal, anonymous tuple, or it may have been written as a
    named `struct`:code:, but there is no way to tell from the compiler
    output.  This class represents a tuple that appeared in a method
    definition.  Its name is derived from a hash of that tuple's field names,
    and every method whose ABI refers to a tuple with that same list of field
    names will have a generated wrapper method that refers to this class.

    Any members of type `bytes`:code: should be encoded as UTF-8, which can be
    accomplished via `str.encode("utf_8")`:code:
    """

    target: str

    callData: Union[bytes, str]


class Multicall2Result(TypedDict):
    """Python representation of a tuple or struct.

    Solidity compiler output does not include the names of structs that appear
    in method definitions.  A tuple found in an ABI may have been written in
    Solidity as a literal, anonymous tuple, or it may have been written as a
    named `struct`:code:, but there is no way to tell from the compiler
    output.  This class represents a tuple that appeared in a method
    definition.  Its name is derived from a hash of that tuple's field names,
    and every method whose ABI refers to a tuple with that same list of field
    names will have a generated wrapper method that refers to this class.

    Any members of type `bytes`:code: should be encoded as UTF-8, which can be
    accomplished via `str.encode("utf_8")`:code:
    """

    success: bool

    returnData: Union[bytes, str]


class AggregateMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the aggregate method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("aggregate")

    def validate_and_normalize_inputs(self, calls: List[Multicall2Call]) -> any:
        """Validate the inputs to the aggregate method."""
        self.validator.assert_valid(
            method_name='aggregate',
            parameter_name='calls',
            argument_value=calls,
        )
        return (calls)

    def block_send(self, calls: List[Multicall2Call], _valeth: int = 0) -> Tuple[int, List[Union[bytes, str]]]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(calls)
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

                self._on_receipt_handle("aggregate", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: aggregate")
            message = f"Error {er}: aggregate"
            self._on_fail("aggregate", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, aggregate: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, aggregate. Reason: Unknown")

            self._on_fail("aggregate", message)

    def send_transaction(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).transact(tx_params.as_dict())

    def build_transaction(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).estimateGas(tx_params.as_dict())


class BlockAndAggregateMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the blockAndAggregate method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("blockAndAggregate")

    def validate_and_normalize_inputs(self, calls: List[Multicall2Call]) -> any:
        """Validate the inputs to the blockAndAggregate method."""
        self.validator.assert_valid(
            method_name='blockAndAggregate',
            parameter_name='calls',
            argument_value=calls,
        )
        return (calls)

    def block_send(self, calls: List[Multicall2Call], _valeth: int = 0) -> Tuple[int, Union[bytes, str], List[Multicall2Result]]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(calls)
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

                self._on_receipt_handle("block_and_aggregate", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: block_and_aggregate")
            message = f"Error {er}: block_and_aggregate"
            self._on_fail("block_and_aggregate", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, block_and_aggregate: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, block_and_aggregate. Reason: Unknown")

            self._on_fail("block_and_aggregate", message)

    def send_transaction(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).transact(tx_params.as_dict())

    def build_transaction(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (calls) = self.validate_and_normalize_inputs(calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(calls).estimateGas(tx_params.as_dict())


class GetBlockHashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getBlockHash method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getBlockHash")

    def validate_and_normalize_inputs(self, block_number: int) -> any:
        """Validate the inputs to the getBlockHash method."""
        self.validator.assert_valid(
            method_name='getBlockHash',
            parameter_name='blockNumber',
            argument_value=block_number,
        )
        # safeguard against fractional inputs
        block_number = int(block_number)
        return (block_number)

    def block_call(self, block_number: int, debug: bool = False) -> Union[bytes, str]:
        _fn = self._underlying_method(block_number)
        returned = _fn.call({
            'from': self._operate
        })
        return Union[bytes, str](returned)

    def estimate_gas(self, block_number: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (block_number) = self.validate_and_normalize_inputs(block_number)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(block_number).estimateGas(tx_params.as_dict())


class GetBlockNumberMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getBlockNumber method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getBlockNumber")

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


class GetCurrentBlockCoinbaseMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCurrentBlockCoinbase method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCurrentBlockCoinbase")

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


class GetCurrentBlockDifficultyMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCurrentBlockDifficulty method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCurrentBlockDifficulty")

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


class GetCurrentBlockGasLimitMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCurrentBlockGasLimit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCurrentBlockGasLimit")

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


class GetCurrentBlockTimestampMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getCurrentBlockTimestamp method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getCurrentBlockTimestamp")

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


class GetEthBalanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getEthBalance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getEthBalance")

    def validate_and_normalize_inputs(self, addr: str) -> any:
        """Validate the inputs to the getEthBalance method."""
        self.validator.assert_valid(
            method_name='getEthBalance',
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


class GetLastBlockHashMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getLastBlockHash method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getLastBlockHash")

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


class TryAggregateMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tryAggregate method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("tryAggregate")

    def validate_and_normalize_inputs(self, require_success: bool, calls: List[Multicall2Call]) -> any:
        """Validate the inputs to the tryAggregate method."""
        self.validator.assert_valid(
            method_name='tryAggregate',
            parameter_name='requireSuccess',
            argument_value=require_success,
        )
        self.validator.assert_valid(
            method_name='tryAggregate',
            parameter_name='calls',
            argument_value=calls,
        )
        return (require_success, calls)

    def block_send(self, require_success: bool, calls: List[Multicall2Call], _valeth: int = 0) -> List[Multicall2Result]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(require_success, calls)
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

                self._on_receipt_handle("try_aggregate", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: try_aggregate")
            message = f"Error {er}: try_aggregate"
            self._on_fail("try_aggregate", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, try_aggregate: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, try_aggregate. Reason: Unknown")

            self._on_fail("try_aggregate", message)

    def send_transaction(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).transact(tx_params.as_dict())

    def build_transaction(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).estimateGas(tx_params.as_dict())


class TryBlockAndAggregateMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tryBlockAndAggregate method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("tryBlockAndAggregate")

    def validate_and_normalize_inputs(self, require_success: bool, calls: List[Multicall2Call]) -> any:
        """Validate the inputs to the tryBlockAndAggregate method."""
        self.validator.assert_valid(
            method_name='tryBlockAndAggregate',
            parameter_name='requireSuccess',
            argument_value=require_success,
        )
        self.validator.assert_valid(
            method_name='tryBlockAndAggregate',
            parameter_name='calls',
            argument_value=calls,
        )
        return (require_success, calls)

    def block_send(self, require_success: bool, calls: List[Multicall2Call], _valeth: int = 0) -> Tuple[int, Union[bytes, str], List[Multicall2Result]]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(require_success, calls)
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

                self._on_receipt_handle("try_block_and_aggregate", tx_receipt, txHash)

            if self.auto_reciept is False:
                time.sleep(self._wait)


        except ContractLogicError as er:
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: try_block_and_aggregate")
            message = f"Error {er}: try_block_and_aggregate"
            self._on_fail("try_block_and_aggregate", message)
        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, try_block_and_aggregate: {message}")
            else:
                message = "Error Revert , Reason: Unknown"
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, try_block_and_aggregate. Reason: Unknown")

            self._on_fail("try_block_and_aggregate", message)

    def send_transaction(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).transact(tx_params.as_dict())

    def build_transaction(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, require_success: bool, calls: List[Multicall2Call], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (require_success, calls) = self.validate_and_normalize_inputs(require_success, calls)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(require_success, calls).estimateGas(tx_params.as_dict())


class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """

    def __init__(self, abi: any):
        super().__init__(abi)

    def aggregate(self) -> str:
        return self._function_signatures["aggregate"]

    def block_and_aggregate(self) -> str:
        return self._function_signatures["blockAndAggregate"]

    def get_block_hash(self) -> str:
        return self._function_signatures["getBlockHash"]

    def get_block_number(self) -> str:
        return self._function_signatures["getBlockNumber"]

    def get_current_block_coinbase(self) -> str:
        return self._function_signatures["getCurrentBlockCoinbase"]

    def get_current_block_difficulty(self) -> str:
        return self._function_signatures["getCurrentBlockDifficulty"]

    def get_current_block_gas_limit(self) -> str:
        return self._function_signatures["getCurrentBlockGasLimit"]

    def get_current_block_timestamp(self) -> str:
        return self._function_signatures["getCurrentBlockTimestamp"]

    def get_eth_balance(self) -> str:
        return self._function_signatures["getEthBalance"]

    def get_last_block_hash(self) -> str:
        return self._function_signatures["getLastBlockHash"]

    def try_aggregate(self) -> str:
        return self._function_signatures["tryAggregate"]

    def try_block_and_aggregate(self) -> str:
        return self._function_signatures["tryBlockAndAggregate"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Multicall2(ContractBase):
    """Wrapper class for Multicall2 Solidity contract."""
    _fn_aggregate: AggregateMethod
    """Constructor-initialized instance of
    :class:`AggregateMethod`.
    """

    _fn_block_and_aggregate: BlockAndAggregateMethod
    """Constructor-initialized instance of
    :class:`BlockAndAggregateMethod`.
    """

    _fn_get_block_hash: GetBlockHashMethod
    """Constructor-initialized instance of
    :class:`GetBlockHashMethod`.
    """

    _fn_get_block_number: GetBlockNumberMethod
    """Constructor-initialized instance of
    :class:`GetBlockNumberMethod`.
    """

    _fn_get_current_block_coinbase: GetCurrentBlockCoinbaseMethod
    """Constructor-initialized instance of
    :class:`GetCurrentBlockCoinbaseMethod`.
    """

    _fn_get_current_block_difficulty: GetCurrentBlockDifficultyMethod
    """Constructor-initialized instance of
    :class:`GetCurrentBlockDifficultyMethod`.
    """

    _fn_get_current_block_gas_limit: GetCurrentBlockGasLimitMethod
    """Constructor-initialized instance of
    :class:`GetCurrentBlockGasLimitMethod`.
    """

    _fn_get_current_block_timestamp: GetCurrentBlockTimestampMethod
    """Constructor-initialized instance of
    :class:`GetCurrentBlockTimestampMethod`.
    """

    _fn_get_eth_balance: GetEthBalanceMethod
    """Constructor-initialized instance of
    :class:`GetEthBalanceMethod`.
    """

    _fn_get_last_block_hash: GetLastBlockHashMethod
    """Constructor-initialized instance of
    :class:`GetLastBlockHashMethod`.
    """

    _fn_try_aggregate: TryAggregateMethod
    """Constructor-initialized instance of
    :class:`TryAggregateMethod`.
    """

    _fn_try_block_and_aggregate: TryBlockAndAggregateMethod
    """Constructor-initialized instance of
    :class:`TryBlockAndAggregateMethod`.
    """

    SIGNATURES: SignatureGenerator = None

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: Multicall2Validator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__(contract_address, Multicall2.abi())
        web3 = core_lib.w3

        if not validator:
            validator = Multicall2Validator(web3, contract_address)

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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Multicall2.abi()).functions
        self._signatures = SignatureGenerator(Multicall2.abi())
        validator.bindSignatures(self._signatures)

        self._fn_aggregate = AggregateMethod(core_lib, contract_address, functions.aggregate, validator)
        self._fn_block_and_aggregate = BlockAndAggregateMethod(core_lib, contract_address, functions.blockAndAggregate, validator)
        self._fn_get_block_hash = GetBlockHashMethod(core_lib, contract_address, functions.getBlockHash, validator)
        self._fn_get_block_number = GetBlockNumberMethod(core_lib, contract_address, functions.getBlockNumber, validator)
        self._fn_get_current_block_coinbase = GetCurrentBlockCoinbaseMethod(core_lib, contract_address, functions.getCurrentBlockCoinbase, validator)
        self._fn_get_current_block_difficulty = GetCurrentBlockDifficultyMethod(core_lib, contract_address, functions.getCurrentBlockDifficulty, validator)
        self._fn_get_current_block_gas_limit = GetCurrentBlockGasLimitMethod(core_lib, contract_address, functions.getCurrentBlockGasLimit, validator)
        self._fn_get_current_block_timestamp = GetCurrentBlockTimestampMethod(core_lib, contract_address, functions.getCurrentBlockTimestamp, validator)
        self._fn_get_eth_balance = GetEthBalanceMethod(core_lib, contract_address, functions.getEthBalance, validator)
        self._fn_get_last_block_hash = GetLastBlockHashMethod(core_lib, contract_address, functions.getLastBlockHash, validator)
        self._fn_try_aggregate = TryAggregateMethod(core_lib, contract_address, functions.tryAggregate, validator)
        self._fn_try_block_and_aggregate = TryBlockAndAggregateMethod(core_lib, contract_address, functions.tryBlockAndAggregate, validator)

    def aggregate(self, calls: List[Multicall2Call]) -> Tuple[int, List[Union[bytes, str]]]:
        """
        Implementation of aggregate in contract Multicall2
        Method of the function

        """

        self._fn_aggregate.callback_onfail = self._callback_onfail
        self._fn_aggregate.callback_onsuccess = self._callback_onsuccess
        self._fn_aggregate.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_aggregate.gas_limit = self.call_contract_fee_amount
        self._fn_aggregate.gas_price_wei = self.call_contract_fee_price
        self._fn_aggregate.debug_method = self.call_contract_debug_flag

        return self._fn_aggregate.block_send(calls)

    def block_and_aggregate(self, calls: List[Multicall2Call]) -> Tuple[int, Union[bytes, str], List[Multicall2Result]]:
        """
        Implementation of block_and_aggregate in contract Multicall2
        Method of the function

        """

        self._fn_block_and_aggregate.callback_onfail = self._callback_onfail
        self._fn_block_and_aggregate.callback_onsuccess = self._callback_onsuccess
        self._fn_block_and_aggregate.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_block_and_aggregate.gas_limit = self.call_contract_fee_amount
        self._fn_block_and_aggregate.gas_price_wei = self.call_contract_fee_price
        self._fn_block_and_aggregate.debug_method = self.call_contract_debug_flag

        return self._fn_block_and_aggregate.block_send(calls)

    def get_block_hash(self, block_number: int) -> Union[bytes, str]:
        """
        Implementation of get_block_hash in contract Multicall2
        Method of the function

        """

        self._fn_get_block_hash.callback_onfail = self._callback_onfail
        self._fn_get_block_hash.callback_onsuccess = self._callback_onsuccess
        self._fn_get_block_hash.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_block_hash.gas_limit = self.call_contract_fee_amount
        self._fn_get_block_hash.gas_price_wei = self.call_contract_fee_price
        self._fn_get_block_hash.debug_method = self.call_contract_debug_flag

        return self._fn_get_block_hash.block_call(block_number)

    def get_block_number(self) -> int:
        """
        Implementation of get_block_number in contract Multicall2
        Method of the function

        """

        self._fn_get_block_number.callback_onfail = self._callback_onfail
        self._fn_get_block_number.callback_onsuccess = self._callback_onsuccess
        self._fn_get_block_number.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_block_number.gas_limit = self.call_contract_fee_amount
        self._fn_get_block_number.gas_price_wei = self.call_contract_fee_price
        self._fn_get_block_number.debug_method = self.call_contract_debug_flag

        return self._fn_get_block_number.block_call()

    def get_current_block_coinbase(self) -> str:
        """
        Implementation of get_current_block_coinbase in contract Multicall2
        Method of the function

        """

        self._fn_get_current_block_coinbase.callback_onfail = self._callback_onfail
        self._fn_get_current_block_coinbase.callback_onsuccess = self._callback_onsuccess
        self._fn_get_current_block_coinbase.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_current_block_coinbase.gas_limit = self.call_contract_fee_amount
        self._fn_get_current_block_coinbase.gas_price_wei = self.call_contract_fee_price
        self._fn_get_current_block_coinbase.debug_method = self.call_contract_debug_flag

        return self._fn_get_current_block_coinbase.block_call()

    def get_current_block_difficulty(self) -> int:
        """
        Implementation of get_current_block_difficulty in contract Multicall2
        Method of the function

        """

        self._fn_get_current_block_difficulty.callback_onfail = self._callback_onfail
        self._fn_get_current_block_difficulty.callback_onsuccess = self._callback_onsuccess
        self._fn_get_current_block_difficulty.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_current_block_difficulty.gas_limit = self.call_contract_fee_amount
        self._fn_get_current_block_difficulty.gas_price_wei = self.call_contract_fee_price
        self._fn_get_current_block_difficulty.debug_method = self.call_contract_debug_flag

        return self._fn_get_current_block_difficulty.block_call()

    def get_current_block_gas_limit(self) -> int:
        """
        Implementation of get_current_block_gas_limit in contract Multicall2
        Method of the function

        """

        self._fn_get_current_block_gas_limit.callback_onfail = self._callback_onfail
        self._fn_get_current_block_gas_limit.callback_onsuccess = self._callback_onsuccess
        self._fn_get_current_block_gas_limit.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_current_block_gas_limit.gas_limit = self.call_contract_fee_amount
        self._fn_get_current_block_gas_limit.gas_price_wei = self.call_contract_fee_price
        self._fn_get_current_block_gas_limit.debug_method = self.call_contract_debug_flag

        return self._fn_get_current_block_gas_limit.block_call()

    def get_current_block_timestamp(self) -> int:
        """
        Implementation of get_current_block_timestamp in contract Multicall2
        Method of the function

        """

        self._fn_get_current_block_timestamp.callback_onfail = self._callback_onfail
        self._fn_get_current_block_timestamp.callback_onsuccess = self._callback_onsuccess
        self._fn_get_current_block_timestamp.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_current_block_timestamp.gas_limit = self.call_contract_fee_amount
        self._fn_get_current_block_timestamp.gas_price_wei = self.call_contract_fee_price
        self._fn_get_current_block_timestamp.debug_method = self.call_contract_debug_flag

        return self._fn_get_current_block_timestamp.block_call()

    def get_eth_balance(self, addr: str) -> int:
        """
        Implementation of get_eth_balance in contract Multicall2
        Method of the function

        """

        self._fn_get_eth_balance.callback_onfail = self._callback_onfail
        self._fn_get_eth_balance.callback_onsuccess = self._callback_onsuccess
        self._fn_get_eth_balance.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_eth_balance.gas_limit = self.call_contract_fee_amount
        self._fn_get_eth_balance.gas_price_wei = self.call_contract_fee_price
        self._fn_get_eth_balance.debug_method = self.call_contract_debug_flag

        return self._fn_get_eth_balance.block_call(addr)

    def get_last_block_hash(self) -> Union[bytes, str]:
        """
        Implementation of get_last_block_hash in contract Multicall2
        Method of the function

        """

        self._fn_get_last_block_hash.callback_onfail = self._callback_onfail
        self._fn_get_last_block_hash.callback_onsuccess = self._callback_onsuccess
        self._fn_get_last_block_hash.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_get_last_block_hash.gas_limit = self.call_contract_fee_amount
        self._fn_get_last_block_hash.gas_price_wei = self.call_contract_fee_price
        self._fn_get_last_block_hash.debug_method = self.call_contract_debug_flag

        return self._fn_get_last_block_hash.block_call()

    def try_aggregate(self, require_success: bool, calls: List[Multicall2Call]) -> List[Multicall2Result]:
        """
        Implementation of try_aggregate in contract Multicall2
        Method of the function

        """

        self._fn_try_aggregate.callback_onfail = self._callback_onfail
        self._fn_try_aggregate.callback_onsuccess = self._callback_onsuccess
        self._fn_try_aggregate.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_try_aggregate.gas_limit = self.call_contract_fee_amount
        self._fn_try_aggregate.gas_price_wei = self.call_contract_fee_price
        self._fn_try_aggregate.debug_method = self.call_contract_debug_flag

        return self._fn_try_aggregate.block_send(require_success, calls)

    def try_block_and_aggregate(self, require_success: bool, calls: List[Multicall2Call]) -> Tuple[int, Union[bytes, str], List[Multicall2Result]]:
        """
        Implementation of try_block_and_aggregate in contract Multicall2
        Method of the function

        """

        self._fn_try_block_and_aggregate.callback_onfail = self._callback_onfail
        self._fn_try_block_and_aggregate.callback_onsuccess = self._callback_onsuccess
        self._fn_try_block_and_aggregate.auto_reciept = self.call_contract_enforce_tx_receipt
        self._fn_try_block_and_aggregate.gas_limit = self.call_contract_fee_amount
        self._fn_try_block_and_aggregate.gas_price_wei = self.call_contract_fee_price
        self._fn_try_block_and_aggregate.debug_method = self.call_contract_debug_flag

        return self._fn_try_block_and_aggregate.block_send(require_success, calls)

    def CallContractWait(self, t_long: int) -> "Multicall2":
        self._fn_aggregate.setWait(t_long)
        self._fn_block_and_aggregate.setWait(t_long)
        self._fn_get_block_hash.setWait(t_long)
        self._fn_get_block_number.setWait(t_long)
        self._fn_get_current_block_coinbase.setWait(t_long)
        self._fn_get_current_block_difficulty.setWait(t_long)
        self._fn_get_current_block_gas_limit.setWait(t_long)
        self._fn_get_current_block_timestamp.setWait(t_long)
        self._fn_get_eth_balance.setWait(t_long)
        self._fn_get_last_block_hash.setWait(t_long)
        self._fn_try_aggregate.setWait(t_long)
        self._fn_try_block_and_aggregate.setWait(t_long)
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"constant":false,"inputs":[{"components":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"callData","type":"bytes"}],"internalType":"struct Multicall2.Call[]","name":"calls","type":"tuple[]"}],"name":"aggregate","outputs":[{"internalType":"uint256","name":"blockNumber","type":"uint256"},{"internalType":"bytes[]","name":"returnData","type":"bytes[]"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"components":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"callData","type":"bytes"}],"internalType":"struct Multicall2.Call[]","name":"calls","type":"tuple[]"}],"name":"blockAndAggregate","outputs":[{"internalType":"uint256","name":"blockNumber","type":"uint256"},{"internalType":"bytes32","name":"blockHash","type":"bytes32"},{"components":[{"internalType":"bool","name":"success","type":"bool"},{"internalType":"bytes","name":"returnData","type":"bytes"}],"internalType":"struct Multicall2.Result[]","name":"returnData","type":"tuple[]"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"blockNumber","type":"uint256"}],"name":"getBlockHash","outputs":[{"internalType":"bytes32","name":"blockHash","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getBlockNumber","outputs":[{"internalType":"uint256","name":"blockNumber","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCurrentBlockCoinbase","outputs":[{"internalType":"address","name":"coinbase","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCurrentBlockDifficulty","outputs":[{"internalType":"uint256","name":"difficulty","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCurrentBlockGasLimit","outputs":[{"internalType":"uint256","name":"gaslimit","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCurrentBlockTimestamp","outputs":[{"internalType":"uint256","name":"timestamp","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"getEthBalance","outputs":[{"internalType":"uint256","name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getLastBlockHash","outputs":[{"internalType":"bytes32","name":"blockHash","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"bool","name":"requireSuccess","type":"bool"},{"components":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"callData","type":"bytes"}],"internalType":"struct Multicall2.Call[]","name":"calls","type":"tuple[]"}],"name":"tryAggregate","outputs":[{"components":[{"internalType":"bool","name":"success","type":"bool"},{"internalType":"bytes","name":"returnData","type":"bytes"}],"internalType":"struct Multicall2.Result[]","name":"returnData","type":"tuple[]"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"bool","name":"requireSuccess","type":"bool"},{"components":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"callData","type":"bytes"}],"internalType":"struct Multicall2.Call[]","name":"calls","type":"tuple[]"}],"name":"tryBlockAndAggregate","outputs":[{"internalType":"uint256","name":"blockNumber","type":"uint256"},{"internalType":"bytes32","name":"blockHash","type":"bytes32"},{"components":[{"internalType":"bool","name":"success","type":"bool"},{"internalType":"bytes","name":"returnData","type":"bytes"}],"internalType":"struct Multicall2.Result[]","name":"returnData","type":"tuple[]"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
