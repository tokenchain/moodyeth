"""Generated wrapper for UniswapV2Factory Solidity contract."""

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
# constructor for UniswapV2Factory below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        UniswapV2FactoryValidator,
    )
except ImportError:

    class UniswapV2FactoryValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass





class AllPairsMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the allPairs method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("allPairs")

    def validate_and_normalize_inputs(self, index_0: int)->any:
        """Validate the inputs to the allPairs method."""
        self.validator.assert_valid(
            method_name='allPairs',
            parameter_name='index_0',
            argument_value=index_0,
        )
        # safeguard against fractional inputs
        index_0 = int(index_0)
        return (index_0)



    def block_call(self,index_0: int, debug:bool=False) -> str:
        _fn = self._underlying_method(index_0)
        returned = _fn.call({
                'from': self._operate
            })
        return str(returned)
    def block_send(self, index_0: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(index_0)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: all_pairs")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, all_pairs: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, all_pairs. Reason: Unknown")


    def send_transaction(self, index_0: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).transact(tx_params.as_dict())

    def build_transaction(self, index_0: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, index_0: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0) = self.validate_and_normalize_inputs(index_0)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0).estimateGas(tx_params.as_dict())

class AllPairsLengthMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the allPairsLength method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("allPairsLength")



    def block_call(self, debug:bool=False) -> int:
        _fn = self._underlying_method()
        returned = _fn.call({
                'from': self._operate
            })
        return int(returned)
    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: all_pairs_length")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, all_pairs_length: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, all_pairs_length. Reason: Unknown")


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

class CreatePairMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the createPair method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("createPair")

    def validate_and_normalize_inputs(self, token_a: str, token_b: str)->any:
        """Validate the inputs to the createPair method."""
        self.validator.assert_valid(
            method_name='createPair',
            parameter_name='tokenA',
            argument_value=token_a,
        )
        token_a = self.validate_and_checksum_address(token_a)
        self.validator.assert_valid(
            method_name='createPair',
            parameter_name='tokenB',
            argument_value=token_b,
        )
        token_b = self.validate_and_checksum_address(token_b)
        return (token_a, token_b)



    def block_send(self, token_a: str, token_b: str,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_a, token_b)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: create_pair")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, create_pair: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, create_pair. Reason: Unknown")


    def send_transaction(self, token_a: str, token_b: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_a, token_b) = self.validate_and_normalize_inputs(token_a, token_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b).transact(tx_params.as_dict())

    def build_transaction(self, token_a: str, token_b: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_a, token_b) = self.validate_and_normalize_inputs(token_a, token_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_a: str, token_b: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_a, token_b) = self.validate_and_normalize_inputs(token_a, token_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b).estimateGas(tx_params.as_dict())

class FeeToMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the feeTo method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("feeTo")



    def block_call(self, debug:bool=False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
                'from': self._operate
            })
        return str(returned)
    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: fee_to")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fee_to: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fee_to. Reason: Unknown")


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

class FeeToSetterMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the feeToSetter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("feeToSetter")



    def block_call(self, debug:bool=False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
                'from': self._operate
            })
        return str(returned)
    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: fee_to_setter")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fee_to_setter: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, fee_to_setter. Reason: Unknown")


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

class GetPairMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getPair method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getPair")

    def validate_and_normalize_inputs(self, index_0: str, index_1: str)->any:
        """Validate the inputs to the getPair method."""
        self.validator.assert_valid(
            method_name='getPair',
            parameter_name='index_0',
            argument_value=index_0,
        )
        index_0 = self.validate_and_checksum_address(index_0)
        self.validator.assert_valid(
            method_name='getPair',
            parameter_name='index_1',
            argument_value=index_1,
        )
        index_1 = self.validate_and_checksum_address(index_1)
        return (index_0, index_1)



    def block_call(self,index_0: str, index_1: str, debug:bool=False) -> str:
        _fn = self._underlying_method(index_0, index_1)
        returned = _fn.call({
                'from': self._operate
            })
        return str(returned)
    def block_send(self, index_0: str, index_1: str,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(index_0, index_1)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_pair")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_pair: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_pair. Reason: Unknown")


    def send_transaction(self, index_0: str, index_1: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (index_0, index_1) = self.validate_and_normalize_inputs(index_0, index_1)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0, index_1).transact(tx_params.as_dict())

    def build_transaction(self, index_0: str, index_1: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (index_0, index_1) = self.validate_and_normalize_inputs(index_0, index_1)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0, index_1).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, index_0: str, index_1: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (index_0, index_1) = self.validate_and_normalize_inputs(index_0, index_1)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(index_0, index_1).estimateGas(tx_params.as_dict())

class MigratorMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the migrator method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("migrator")



    def block_call(self, debug:bool=False) -> str:
        _fn = self._underlying_method()
        returned = _fn.call({
                'from': self._operate
            })
        return str(returned)
    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> str:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: migrator")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, migrator: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, migrator. Reason: Unknown")


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

class PairCodeHashMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the pairCodeHash method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("pairCodeHash")


    def block_call(self, debug:bool=False) -> Union[bytes, str]:
        _fn = self._underlying_method()
        returned = _fn.call({
                'from': self._operate
            })
        return Union[bytes, str](returned)

    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Union[bytes, str]:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: pair_code_hash")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, pair_code_hash: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, pair_code_hash. Reason: Unknown")


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

class SetFeeToMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the setFeeTo method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setFeeTo")

    def validate_and_normalize_inputs(self, fee_to: str)->any:
        """Validate the inputs to the setFeeTo method."""
        self.validator.assert_valid(
            method_name='setFeeTo',
            parameter_name='_feeTo',
            argument_value=fee_to,
        )
        fee_to = self.validate_and_checksum_address(fee_to)
        return (fee_to)



    def block_send(self, fee_to: str,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(fee_to)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_fee_to")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fee_to: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fee_to. Reason: Unknown")


    def send_transaction(self, fee_to: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (fee_to) = self.validate_and_normalize_inputs(fee_to)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to).transact(tx_params.as_dict())

    def build_transaction(self, fee_to: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (fee_to) = self.validate_and_normalize_inputs(fee_to)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, fee_to: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (fee_to) = self.validate_and_normalize_inputs(fee_to)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to).estimateGas(tx_params.as_dict())

class SetFeeToSetterMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the setFeeToSetter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setFeeToSetter")

    def validate_and_normalize_inputs(self, fee_to_setter: str)->any:
        """Validate the inputs to the setFeeToSetter method."""
        self.validator.assert_valid(
            method_name='setFeeToSetter',
            parameter_name='_feeToSetter',
            argument_value=fee_to_setter,
        )
        fee_to_setter = self.validate_and_checksum_address(fee_to_setter)
        return (fee_to_setter)



    def block_send(self, fee_to_setter: str,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(fee_to_setter)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_fee_to_setter")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fee_to_setter: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_fee_to_setter. Reason: Unknown")


    def send_transaction(self, fee_to_setter: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (fee_to_setter) = self.validate_and_normalize_inputs(fee_to_setter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to_setter).transact(tx_params.as_dict())

    def build_transaction(self, fee_to_setter: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (fee_to_setter) = self.validate_and_normalize_inputs(fee_to_setter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to_setter).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, fee_to_setter: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (fee_to_setter) = self.validate_and_normalize_inputs(fee_to_setter)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(fee_to_setter).estimateGas(tx_params.as_dict())

class SetMigratorMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the setMigrator method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("setMigrator")

    def validate_and_normalize_inputs(self, migrator: str)->any:
        """Validate the inputs to the setMigrator method."""
        self.validator.assert_valid(
            method_name='setMigrator',
            parameter_name='_migrator',
            argument_value=migrator,
        )
        migrator = self.validate_and_checksum_address(migrator)
        return (migrator)



    def block_send(self, migrator: str,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(migrator)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: set_migrator")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_migrator: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, set_migrator. Reason: Unknown")


    def send_transaction(self, migrator: str, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (migrator) = self.validate_and_normalize_inputs(migrator)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(migrator).transact(tx_params.as_dict())

    def build_transaction(self, migrator: str, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (migrator) = self.validate_and_normalize_inputs(migrator)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(migrator).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, migrator: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (migrator) = self.validate_and_normalize_inputs(migrator)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(migrator).estimateGas(tx_params.as_dict())

class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """
    def __init__(self, abi: any):
        super().__init__(abi)

    def all_pairs(self) -> str:
        return self._function_signatures["allPairs"]
    def all_pairs_length(self) -> str:
        return self._function_signatures["allPairsLength"]
    def create_pair(self) -> str:
        return self._function_signatures["createPair"]
    def fee_to(self) -> str:
        return self._function_signatures["feeTo"]
    def fee_to_setter(self) -> str:
        return self._function_signatures["feeToSetter"]
    def get_pair(self) -> str:
        return self._function_signatures["getPair"]
    def migrator(self) -> str:
        return self._function_signatures["migrator"]
    def pair_code_hash(self) -> str:
        return self._function_signatures["pairCodeHash"]
    def set_fee_to(self) -> str:
        return self._function_signatures["setFeeTo"]
    def set_fee_to_setter(self) -> str:
        return self._function_signatures["setFeeToSetter"]
    def set_migrator(self) -> str:
        return self._function_signatures["setMigrator"]

# pylint: disable=too-many-public-methods,too-many-instance-attributes
class UniswapV2Factory(ContractBase):
    """Wrapper class for UniswapV2Factory Solidity contract."""
    _fn_all_pairs: AllPairsMethod
    """Constructor-initialized instance of
    :class:`AllPairsMethod`.
    """

    _fn_all_pairs_length: AllPairsLengthMethod
    """Constructor-initialized instance of
    :class:`AllPairsLengthMethod`.
    """

    _fn_create_pair: CreatePairMethod
    """Constructor-initialized instance of
    :class:`CreatePairMethod`.
    """

    _fn_fee_to: FeeToMethod
    """Constructor-initialized instance of
    :class:`FeeToMethod`.
    """

    _fn_fee_to_setter: FeeToSetterMethod
    """Constructor-initialized instance of
    :class:`FeeToSetterMethod`.
    """

    _fn_get_pair: GetPairMethod
    """Constructor-initialized instance of
    :class:`GetPairMethod`.
    """

    _fn_migrator: MigratorMethod
    """Constructor-initialized instance of
    :class:`MigratorMethod`.
    """

    _fn_pair_code_hash: PairCodeHashMethod
    """Constructor-initialized instance of
    :class:`PairCodeHashMethod`.
    """

    _fn_set_fee_to: SetFeeToMethod
    """Constructor-initialized instance of
    :class:`SetFeeToMethod`.
    """

    _fn_set_fee_to_setter: SetFeeToSetterMethod
    """Constructor-initialized instance of
    :class:`SetFeeToSetterMethod`.
    """

    _fn_set_migrator: SetMigratorMethod
    """Constructor-initialized instance of
    :class:`SetMigratorMethod`.
    """

    SIGNATURES:SignatureGenerator = None

    def __init__(
        self,
        core_lib: MiliDoS,
        contract_address: str,
        validator: UniswapV2FactoryValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = UniswapV2FactoryValidator(web3, contract_address)




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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=UniswapV2Factory.abi()).functions
        signed = SignatureGenerator(UniswapV2Factory.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_all_pairs = AllPairsMethod(core_lib, contract_address, functions.allPairs, validator)
        self._fn_all_pairs_length = AllPairsLengthMethod(core_lib, contract_address, functions.allPairsLength, validator)
        self._fn_create_pair = CreatePairMethod(core_lib, contract_address, functions.createPair, validator)
        self._fn_fee_to = FeeToMethod(core_lib, contract_address, functions.feeTo, validator)
        self._fn_fee_to_setter = FeeToSetterMethod(core_lib, contract_address, functions.feeToSetter, validator)
        self._fn_get_pair = GetPairMethod(core_lib, contract_address, functions.getPair, validator)
        self._fn_migrator = MigratorMethod(core_lib, contract_address, functions.migrator, validator)
        self._fn_pair_code_hash = PairCodeHashMethod(core_lib, contract_address, functions.pairCodeHash, validator)
        self._fn_set_fee_to = SetFeeToMethod(core_lib, contract_address, functions.setFeeTo, validator)
        self._fn_set_fee_to_setter = SetFeeToSetterMethod(core_lib, contract_address, functions.setFeeToSetter, validator)
        self._fn_set_migrator = SetMigratorMethod(core_lib, contract_address, functions.setMigrator, validator)

    
    
    def event_pair_created(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event pair_created in contract UniswapV2Factory
        Get log entry for PairCreated event.
                :param tx_hash: hash of transaction emitting PairCreated event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=UniswapV2Factory.abi()).events.PairCreated().processReceipt(tx_receipt)

    
    
    
    def all_pairs(self, index_0: int) -> str:
        """
        Implementation of all_pairs in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_all_pairs.block_call(index_0)
    
    
    
    def all_pairs_length(self) -> int:
        """
        Implementation of all_pairs_length in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_all_pairs_length.block_call()
    
    
    
    def create_pair(self, token_a: str, token_b: str) -> str:
        """
        Implementation of create_pair in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
        return self._fn_create_pair.block_send(token_a, token_b, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def fee_to(self) -> str:
        """
        Implementation of fee_to in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_fee_to.block_call()
    
    
    
    def fee_to_setter(self) -> str:
        """
        Implementation of fee_to_setter in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_fee_to_setter.block_call()
    
    
    
    def get_pair(self, index_0: str, index_1: str) -> str:
        """
        Implementation of get_pair in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_get_pair.block_call(index_0, index_1)
    
    
    
    def migrator(self) -> str:
        """
        Implementation of migrator in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_migrator.block_call()
    
    
    
    def pair_code_hash(self) -> Union[bytes, str]:
        """
        Implementation of pair_code_hash in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
    
    
        return self._fn_pair_code_hash.block_call()
    
    
    
    
    
    def set_fee_to(self, fee_to: str) -> None:
        """
        Implementation of set_fee_to in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
        return self._fn_set_fee_to.block_send(fee_to, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def set_fee_to_setter(self, fee_to_setter: str) -> None:
        """
        Implementation of set_fee_to_setter in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
        return self._fn_set_fee_to_setter.block_send(fee_to_setter, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def set_migrator(self, migrator: str) -> None:
        """
        Implementation of set_migrator in contract UniswapV2Factory
        Method of the function
    
    
    
        """
    
        return self._fn_set_migrator.block_send(migrator, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    

    def CallContractWait(self, t_long:int)-> "UniswapV2Factory":
        self._fn_all_pairs.setWait(t_long)
        self._fn_all_pairs_length.setWait(t_long)
        self._fn_create_pair.setWait(t_long)
        self._fn_fee_to.setWait(t_long)
        self._fn_fee_to_setter.setWait(t_long)
        self._fn_get_pair.setWait(t_long)
        self._fn_migrator.setWait(t_long)
        self._fn_pair_code_hash.setWait(t_long)
        self._fn_set_fee_to.setWait(t_long)
        self._fn_set_fee_to_setter.setWait(t_long)
        self._fn_set_migrator.setWait(t_long)
        return self


    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"_feeToSetter","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"token0","type":"address"},{"indexed":true,"internalType":"address","name":"token1","type":"address"},{"indexed":false,"internalType":"address","name":"pair","type":"address"},{"indexed":false,"internalType":"uint256","name":"","type":"uint256"}],"name":"PairCreated","type":"event"},{"inputs":[{"internalType":"uint256","name":"index_0","type":"uint256"}],"name":"allPairs","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"allPairsLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"}],"name":"createPair","outputs":[{"internalType":"address","name":"pair","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"feeTo","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"feeToSetter","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"index_0","type":"address"},{"internalType":"address","name":"index_1","type":"address"}],"name":"getPair","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"migrator","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pairCodeHash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"_feeTo","type":"address"}],"name":"setFeeTo","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_feeToSetter","type":"address"}],"name":"setFeeToSetter","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_migrator","type":"address"}],"name":"setMigrator","outputs":[],"stateMutability":"nonpayable","type":"function"}]'  # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
