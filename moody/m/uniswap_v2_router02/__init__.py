"""Generated wrapper for UniswapV2Router02 Solidity contract."""

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
# constructor for UniswapV2Router02 below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        UniswapV2Router02Validator,
    )
except ImportError:

    class UniswapV2Router02Validator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass





class WethMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the WETH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("WETH")



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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: weth")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, weth: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, weth. Reason: Unknown")


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

class AddLiquidityMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the addLiquidity method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addLiquidity")

    def validate_and_normalize_inputs(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int)->any:
        """Validate the inputs to the addLiquidity method."""
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='tokenA',
            argument_value=token_a,
        )
        token_a = self.validate_and_checksum_address(token_a)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='tokenB',
            argument_value=token_b,
        )
        token_b = self.validate_and_checksum_address(token_b)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='amountADesired',
            argument_value=amount_a_desired,
        )
        # safeguard against fractional inputs
        amount_a_desired = int(amount_a_desired)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='amountBDesired',
            argument_value=amount_b_desired,
        )
        # safeguard against fractional inputs
        amount_b_desired = int(amount_b_desired)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='amountAMin',
            argument_value=amount_a_min,
        )
        # safeguard against fractional inputs
        amount_a_min = int(amount_a_min)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='amountBMin',
            argument_value=amount_b_min,
        )
        # safeguard against fractional inputs
        amount_b_min = int(amount_b_min)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='addLiquidity',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline)



    def block_send(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_liquidity")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_liquidity: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_liquidity. Reason: Unknown")


    def send_transaction(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline).estimateGas(tx_params.as_dict())

class AddLiquidityEthMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the addLiquidityETH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("addLiquidityETH")

    def validate_and_normalize_inputs(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int)->any:
        """Validate the inputs to the addLiquidityETH method."""
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='token',
            argument_value=token,
        )
        token = self.validate_and_checksum_address(token)
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='amountTokenDesired',
            argument_value=amount_token_desired,
        )
        # safeguard against fractional inputs
        amount_token_desired = int(amount_token_desired)
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='amountTokenMin',
            argument_value=amount_token_min,
        )
        # safeguard against fractional inputs
        amount_token_min = int(amount_token_min)
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='amountETHMin',
            argument_value=amount_eth_min,
        )
        # safeguard against fractional inputs
        amount_eth_min = int(amount_eth_min)
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='addLiquidityETH',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline)



    def block_send(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: add_liquidity_eth")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_liquidity_eth: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, add_liquidity_eth. Reason: Unknown")


    def send_transaction(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline).estimateGas(tx_params.as_dict())

class FactoryMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the factory method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("factory")



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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: factory")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, factory: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, factory. Reason: Unknown")


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

class GetAmountInMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getAmountIn method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAmountIn")

    def validate_and_normalize_inputs(self, amount_out: int, reserve_in: int, reserve_out: int)->any:
        """Validate the inputs to the getAmountIn method."""
        self.validator.assert_valid(
            method_name='getAmountIn',
            parameter_name='amountOut',
            argument_value=amount_out,
        )
        # safeguard against fractional inputs
        amount_out = int(amount_out)
        self.validator.assert_valid(
            method_name='getAmountIn',
            parameter_name='reserveIn',
            argument_value=reserve_in,
        )
        # safeguard against fractional inputs
        reserve_in = int(reserve_in)
        self.validator.assert_valid(
            method_name='getAmountIn',
            parameter_name='reserveOut',
            argument_value=reserve_out,
        )
        # safeguard against fractional inputs
        reserve_out = int(reserve_out)
        return (amount_out, reserve_in, reserve_out)


    def block_call(self,amount_out: int, reserve_in: int, reserve_out: int, debug:bool=False) -> int:
        _fn = self._underlying_method(amount_out, reserve_in, reserve_out)
        returned = _fn.call({
                'from': self._operate
            })
        return int(returned)

    def block_send(self, amount_out: int, reserve_in: int, reserve_out: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out, reserve_in, reserve_out)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_amount_in")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amount_in: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amount_in. Reason: Unknown")


    def send_transaction(self, amount_out: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_out, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, reserve_in, reserve_out).transact(tx_params.as_dict())

    def build_transaction(self, amount_out: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_out, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, reserve_in, reserve_out).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_out, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, reserve_in, reserve_out).estimateGas(tx_params.as_dict())

class GetAmountOutMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getAmountOut method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAmountOut")

    def validate_and_normalize_inputs(self, amount_in: int, reserve_in: int, reserve_out: int)->any:
        """Validate the inputs to the getAmountOut method."""
        self.validator.assert_valid(
            method_name='getAmountOut',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='getAmountOut',
            parameter_name='reserveIn',
            argument_value=reserve_in,
        )
        # safeguard against fractional inputs
        reserve_in = int(reserve_in)
        self.validator.assert_valid(
            method_name='getAmountOut',
            parameter_name='reserveOut',
            argument_value=reserve_out,
        )
        # safeguard against fractional inputs
        reserve_out = int(reserve_out)
        return (amount_in, reserve_in, reserve_out)


    def block_call(self,amount_in: int, reserve_in: int, reserve_out: int, debug:bool=False) -> int:
        _fn = self._underlying_method(amount_in, reserve_in, reserve_out)
        returned = _fn.call({
                'from': self._operate
            })
        return int(returned)

    def block_send(self, amount_in: int, reserve_in: int, reserve_out: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, reserve_in, reserve_out)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_amount_out")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amount_out: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amount_out. Reason: Unknown")


    def send_transaction(self, amount_in: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_in, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, reserve_in, reserve_out).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_in, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, reserve_in, reserve_out).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, reserve_in: int, reserve_out: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, reserve_in, reserve_out) = self.validate_and_normalize_inputs(amount_in, reserve_in, reserve_out)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, reserve_in, reserve_out).estimateGas(tx_params.as_dict())

class GetAmountsInMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getAmountsIn method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAmountsIn")

    def validate_and_normalize_inputs(self, amount_out: int, path: List[str])->any:
        """Validate the inputs to the getAmountsIn method."""
        self.validator.assert_valid(
            method_name='getAmountsIn',
            parameter_name='amountOut',
            argument_value=amount_out,
        )
        # safeguard against fractional inputs
        amount_out = int(amount_out)
        self.validator.assert_valid(
            method_name='getAmountsIn',
            parameter_name='path',
            argument_value=path,
        )
        return (amount_out, path)



    def block_call(self,amount_out: int, path: List[str], debug:bool=False) -> List[int]:
        _fn = self._underlying_method(amount_out, path)
        returned = _fn.call({
                'from': self._operate
            })
        return [int(element) for element in returned]
    def block_send(self, amount_out: int, path: List[str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out, path)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_amounts_in")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amounts_in: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amounts_in. Reason: Unknown")


    def send_transaction(self, amount_out: int, path: List[str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out, path) = self.validate_and_normalize_inputs(amount_out, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path).transact(tx_params.as_dict())

    def build_transaction(self, amount_out: int, path: List[str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out, path) = self.validate_and_normalize_inputs(amount_out, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out: int, path: List[str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out, path) = self.validate_and_normalize_inputs(amount_out, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path).estimateGas(tx_params.as_dict())

class GetAmountsOutMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getAmountsOut method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getAmountsOut")

    def validate_and_normalize_inputs(self, amount_in: int, path: List[str])->any:
        """Validate the inputs to the getAmountsOut method."""
        self.validator.assert_valid(
            method_name='getAmountsOut',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='getAmountsOut',
            parameter_name='path',
            argument_value=path,
        )
        return (amount_in, path)



    def block_call(self,amount_in: int, path: List[str], debug:bool=False) -> List[int]:
        _fn = self._underlying_method(amount_in, path)
        returned = _fn.call({
                'from': self._operate
            })
        return [int(element) for element in returned]
    def block_send(self, amount_in: int, path: List[str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, path)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_amounts_out")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amounts_out: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_amounts_out. Reason: Unknown")


    def send_transaction(self, amount_in: int, path: List[str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, path) = self.validate_and_normalize_inputs(amount_in, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, path).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, path: List[str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, path) = self.validate_and_normalize_inputs(amount_in, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, path).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, path: List[str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, path) = self.validate_and_normalize_inputs(amount_in, path)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, path).estimateGas(tx_params.as_dict())

class QuoteMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the quote method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("quote")

    def validate_and_normalize_inputs(self, amount_a: int, reserve_a: int, reserve_b: int)->any:
        """Validate the inputs to the quote method."""
        self.validator.assert_valid(
            method_name='quote',
            parameter_name='amountA',
            argument_value=amount_a,
        )
        # safeguard against fractional inputs
        amount_a = int(amount_a)
        self.validator.assert_valid(
            method_name='quote',
            parameter_name='reserveA',
            argument_value=reserve_a,
        )
        # safeguard against fractional inputs
        reserve_a = int(reserve_a)
        self.validator.assert_valid(
            method_name='quote',
            parameter_name='reserveB',
            argument_value=reserve_b,
        )
        # safeguard against fractional inputs
        reserve_b = int(reserve_b)
        return (amount_a, reserve_a, reserve_b)


    def block_call(self,amount_a: int, reserve_a: int, reserve_b: int, debug:bool=False) -> int:
        _fn = self._underlying_method(amount_a, reserve_a, reserve_b)
        returned = _fn.call({
                'from': self._operate
            })
        return int(returned)

    def block_send(self, amount_a: int, reserve_a: int, reserve_b: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_a, reserve_a, reserve_b)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: quote")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, quote: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, quote. Reason: Unknown")


    def send_transaction(self, amount_a: int, reserve_a: int, reserve_b: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_a, reserve_a, reserve_b) = self.validate_and_normalize_inputs(amount_a, reserve_a, reserve_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_a, reserve_a, reserve_b).transact(tx_params.as_dict())

    def build_transaction(self, amount_a: int, reserve_a: int, reserve_b: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_a, reserve_a, reserve_b) = self.validate_and_normalize_inputs(amount_a, reserve_a, reserve_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_a, reserve_a, reserve_b).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_a: int, reserve_a: int, reserve_b: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_a, reserve_a, reserve_b) = self.validate_and_normalize_inputs(amount_a, reserve_a, reserve_b)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_a, reserve_a, reserve_b).estimateGas(tx_params.as_dict())

class RemoveLiquidityMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidity method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidity")

    def validate_and_normalize_inputs(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int)->any:
        """Validate the inputs to the removeLiquidity method."""
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='tokenA',
            argument_value=token_a,
        )
        token_a = self.validate_and_checksum_address(token_a)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='tokenB',
            argument_value=token_b,
        )
        token_b = self.validate_and_checksum_address(token_b)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='amountAMin',
            argument_value=amount_a_min,
        )
        # safeguard against fractional inputs
        amount_a_min = int(amount_a_min)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='amountBMin',
            argument_value=amount_b_min,
        )
        # safeguard against fractional inputs
        amount_b_min = int(amount_b_min)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidity',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline)



    def block_send(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity. Reason: Unknown")


    def send_transaction(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline).estimateGas(tx_params.as_dict())

class RemoveLiquidityEthMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidityETH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidityETH")

    def validate_and_normalize_inputs(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int)->any:
        """Validate the inputs to the removeLiquidityETH method."""
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='token',
            argument_value=token,
        )
        token = self.validate_and_checksum_address(token)
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='amountTokenMin',
            argument_value=amount_token_min,
        )
        # safeguard against fractional inputs
        amount_token_min = int(amount_token_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='amountETHMin',
            argument_value=amount_eth_min,
        )
        # safeguard against fractional inputs
        amount_eth_min = int(amount_eth_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidityETH',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (token, liquidity, amount_token_min, amount_eth_min, to, deadline)



    def block_send(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity_eth")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth. Reason: Unknown")


    def send_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).estimateGas(tx_params.as_dict())

class RemoveLiquidityEthSupportingFeeOnTransferTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidityETHSupportingFeeOnTransferTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidityETHSupportingFeeOnTransferTokens")

    def validate_and_normalize_inputs(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int)->any:
        """Validate the inputs to the removeLiquidityETHSupportingFeeOnTransferTokens method."""
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='token',
            argument_value=token,
        )
        token = self.validate_and_checksum_address(token)
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='amountTokenMin',
            argument_value=amount_token_min,
        )
        # safeguard against fractional inputs
        amount_token_min = int(amount_token_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='amountETHMin',
            argument_value=amount_eth_min,
        )
        # safeguard against fractional inputs
        amount_eth_min = int(amount_eth_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidityETHSupportingFeeOnTransferTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (token, liquidity, amount_token_min, amount_eth_min, to, deadline)



    def block_send(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity_eth_supporting_fee_on_transfer_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_supporting_fee_on_transfer_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_supporting_fee_on_transfer_tokens. Reason: Unknown")


    def send_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline).estimateGas(tx_params.as_dict())

class RemoveLiquidityEthWithPermitMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidityETHWithPermit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidityETHWithPermit")

    def validate_and_normalize_inputs(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str])->any:
        """Validate the inputs to the removeLiquidityETHWithPermit method."""
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='token',
            argument_value=token,
        )
        token = self.validate_and_checksum_address(token)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='amountTokenMin',
            argument_value=amount_token_min,
        )
        # safeguard against fractional inputs
        amount_token_min = int(amount_token_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='amountETHMin',
            argument_value=amount_eth_min,
        )
        # safeguard against fractional inputs
        amount_eth_min = int(amount_eth_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='approveMax',
            argument_value=approve_max,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='v',
            argument_value=v,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='r',
            argument_value=r,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermit',
            parameter_name='s',
            argument_value=s,
        )
        return (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)



    def block_send(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity_eth_with_permit")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_with_permit: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_with_permit. Reason: Unknown")


    def send_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).transact(tx_params.as_dict())

    def build_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).estimateGas(tx_params.as_dict())

class RemoveLiquidityEthWithPermitSupportingFeeOnTransferTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidityETHWithPermitSupportingFeeOnTransferTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidityETHWithPermitSupportingFeeOnTransferTokens")

    def validate_and_normalize_inputs(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str])->any:
        """Validate the inputs to the removeLiquidityETHWithPermitSupportingFeeOnTransferTokens method."""
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='token',
            argument_value=token,
        )
        token = self.validate_and_checksum_address(token)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='amountTokenMin',
            argument_value=amount_token_min,
        )
        # safeguard against fractional inputs
        amount_token_min = int(amount_token_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='amountETHMin',
            argument_value=amount_eth_min,
        )
        # safeguard against fractional inputs
        amount_eth_min = int(amount_eth_min)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='approveMax',
            argument_value=approve_max,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='v',
            argument_value=v,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='r',
            argument_value=r,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityETHWithPermitSupportingFeeOnTransferTokens',
            parameter_name='s',
            argument_value=s,
        )
        return (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)



    def block_send(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens. Reason: Unknown")


    def send_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).transact(tx_params.as_dict())

    def build_transaction(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s).estimateGas(tx_params.as_dict())

class RemoveLiquidityWithPermitMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the removeLiquidityWithPermit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("removeLiquidityWithPermit")

    def validate_and_normalize_inputs(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str])->any:
        """Validate the inputs to the removeLiquidityWithPermit method."""
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='tokenA',
            argument_value=token_a,
        )
        token_a = self.validate_and_checksum_address(token_a)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='tokenB',
            argument_value=token_b,
        )
        token_b = self.validate_and_checksum_address(token_b)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='liquidity',
            argument_value=liquidity,
        )
        # safeguard against fractional inputs
        liquidity = int(liquidity)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='amountAMin',
            argument_value=amount_a_min,
        )
        # safeguard against fractional inputs
        amount_a_min = int(amount_a_min)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='amountBMin',
            argument_value=amount_b_min,
        )
        # safeguard against fractional inputs
        amount_b_min = int(amount_b_min)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='approveMax',
            argument_value=approve_max,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='v',
            argument_value=v,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='r',
            argument_value=r,
        )
        self.validator.assert_valid(
            method_name='removeLiquidityWithPermit',
            parameter_name='s',
            argument_value=s,
        )
        return (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s)



    def block_send(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Tuple[int, int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: remove_liquidity_with_permit")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_with_permit: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, remove_liquidity_with_permit. Reason: Unknown")


    def send_transaction(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s).transact(tx_params.as_dict())

    def build_transaction(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s) = self.validate_and_normalize_inputs(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s).estimateGas(tx_params.as_dict())

class SwapEthForExactTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapETHForExactTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapETHForExactTokens")

    def validate_and_normalize_inputs(self, amount_out: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapETHForExactTokens method."""
        self.validator.assert_valid(
            method_name='swapETHForExactTokens',
            parameter_name='amountOut',
            argument_value=amount_out,
        )
        # safeguard against fractional inputs
        amount_out = int(amount_out)
        self.validator.assert_valid(
            method_name='swapETHForExactTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapETHForExactTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapETHForExactTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_out, path, to, deadline)



    def block_send(self, amount_out: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_eth_for_exact_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_eth_for_exact_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_eth_for_exact_tokens. Reason: Unknown")


    def send_transaction(self, amount_out: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_out: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactEthForTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactETHForTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactETHForTokens")

    def validate_and_normalize_inputs(self, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactETHForTokens method."""
        self.validator.assert_valid(
            method_name='swapExactETHForTokens',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactETHForTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactETHForTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactETHForTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_out_min, path, to, deadline)



    def block_send(self, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_eth_for_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_eth_for_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_eth_for_tokens. Reason: Unknown")


    def send_transaction(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactEthForTokensSupportingFeeOnTransferTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactETHForTokensSupportingFeeOnTransferTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactETHForTokensSupportingFeeOnTransferTokens")

    def validate_and_normalize_inputs(self, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactETHForTokensSupportingFeeOnTransferTokens method."""
        self.validator.assert_valid(
            method_name='swapExactETHForTokensSupportingFeeOnTransferTokens',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactETHForTokensSupportingFeeOnTransferTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactETHForTokensSupportingFeeOnTransferTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactETHForTokensSupportingFeeOnTransferTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_out_min, path, to, deadline)



    def block_send(self, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens. Reason: Unknown")


    def send_transaction(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactTokensForEthMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactTokensForETH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactTokensForETH")

    def validate_and_normalize_inputs(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactTokensForETH method."""
        self.validator.assert_valid(
            method_name='swapExactTokensForETH',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='swapExactTokensForETH',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactTokensForETH',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactTokensForETH',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactTokensForETH',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_in, amount_out_min, path, to, deadline)



    def block_send(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_tokens_for_eth")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_eth: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_eth. Reason: Unknown")


    def send_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactTokensForEthSupportingFeeOnTransferTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactTokensForETHSupportingFeeOnTransferTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactTokensForETHSupportingFeeOnTransferTokens")

    def validate_and_normalize_inputs(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactTokensForETHSupportingFeeOnTransferTokens method."""
        self.validator.assert_valid(
            method_name='swapExactTokensForETHSupportingFeeOnTransferTokens',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='swapExactTokensForETHSupportingFeeOnTransferTokens',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactTokensForETHSupportingFeeOnTransferTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactTokensForETHSupportingFeeOnTransferTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactTokensForETHSupportingFeeOnTransferTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_in, amount_out_min, path, to, deadline)



    def block_send(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens. Reason: Unknown")


    def send_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactTokensForTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactTokensForTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactTokensForTokens")

    def validate_and_normalize_inputs(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactTokensForTokens method."""
        self.validator.assert_valid(
            method_name='swapExactTokensForTokens',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokens',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactTokensForTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_in, amount_out_min, path, to, deadline)



    def block_send(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_tokens_for_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_tokens. Reason: Unknown")


    def send_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapExactTokensForTokensSupportingFeeOnTransferTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapExactTokensForTokensSupportingFeeOnTransferTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapExactTokensForTokensSupportingFeeOnTransferTokens")

    def validate_and_normalize_inputs(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapExactTokensForTokensSupportingFeeOnTransferTokens method."""
        self.validator.assert_valid(
            method_name='swapExactTokensForTokensSupportingFeeOnTransferTokens',
            parameter_name='amountIn',
            argument_value=amount_in,
        )
        # safeguard against fractional inputs
        amount_in = int(amount_in)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokensSupportingFeeOnTransferTokens',
            parameter_name='amountOutMin',
            argument_value=amount_out_min,
        )
        # safeguard against fractional inputs
        amount_out_min = int(amount_out_min)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokensSupportingFeeOnTransferTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapExactTokensForTokensSupportingFeeOnTransferTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapExactTokensForTokensSupportingFeeOnTransferTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_in, amount_out_min, path, to, deadline)



    def block_send(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_in, amount_out_min, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens. Reason: Unknown")


    def send_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_in, amount_out_min, path, to, deadline) = self.validate_and_normalize_inputs(amount_in, amount_out_min, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_in, amount_out_min, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapTokensForExactEthMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapTokensForExactETH method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapTokensForExactETH")

    def validate_and_normalize_inputs(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapTokensForExactETH method."""
        self.validator.assert_valid(
            method_name='swapTokensForExactETH',
            parameter_name='amountOut',
            argument_value=amount_out,
        )
        # safeguard against fractional inputs
        amount_out = int(amount_out)
        self.validator.assert_valid(
            method_name='swapTokensForExactETH',
            parameter_name='amountInMax',
            argument_value=amount_in_max,
        )
        # safeguard against fractional inputs
        amount_in_max = int(amount_in_max)
        self.validator.assert_valid(
            method_name='swapTokensForExactETH',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapTokensForExactETH',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapTokensForExactETH',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_out, amount_in_max, path, to, deadline)



    def block_send(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out, amount_in_max, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_tokens_for_exact_eth")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_tokens_for_exact_eth: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_tokens_for_exact_eth. Reason: Unknown")


    def send_transaction(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).estimateGas(tx_params.as_dict())

class SwapTokensForExactTokensMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the swapTokensForExactTokens method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("swapTokensForExactTokens")

    def validate_and_normalize_inputs(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int)->any:
        """Validate the inputs to the swapTokensForExactTokens method."""
        self.validator.assert_valid(
            method_name='swapTokensForExactTokens',
            parameter_name='amountOut',
            argument_value=amount_out,
        )
        # safeguard against fractional inputs
        amount_out = int(amount_out)
        self.validator.assert_valid(
            method_name='swapTokensForExactTokens',
            parameter_name='amountInMax',
            argument_value=amount_in_max,
        )
        # safeguard against fractional inputs
        amount_in_max = int(amount_in_max)
        self.validator.assert_valid(
            method_name='swapTokensForExactTokens',
            parameter_name='path',
            argument_value=path,
        )
        self.validator.assert_valid(
            method_name='swapTokensForExactTokens',
            parameter_name='to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='swapTokensForExactTokens',
            parameter_name='deadline',
            argument_value=deadline,
        )
        # safeguard against fractional inputs
        deadline = int(deadline)
        return (amount_out, amount_in_max, path, to, deadline)



    def block_send(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> List[int]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(amount_out, amount_in_max, path, to, deadline)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: swap_tokens_for_exact_tokens")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_tokens_for_exact_tokens: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, swap_tokens_for_exact_tokens. Reason: Unknown")


    def send_transaction(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).transact(tx_params.as_dict())

    def build_transaction(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount_out, amount_in_max, path, to, deadline) = self.validate_and_normalize_inputs(amount_out, amount_in_max, path, to, deadline)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount_out, amount_in_max, path, to, deadline).estimateGas(tx_params.as_dict())

class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """
    def __init__(self, abi: any):
        super().__init__(abi)

    def weth(self) -> str:
        return self._function_signatures["WETH"]
    def add_liquidity(self) -> str:
        return self._function_signatures["addLiquidity"]
    def add_liquidity_eth(self) -> str:
        return self._function_signatures["addLiquidityETH"]
    def factory(self) -> str:
        return self._function_signatures["factory"]
    def get_amount_in(self) -> str:
        return self._function_signatures["getAmountIn"]
    def get_amount_out(self) -> str:
        return self._function_signatures["getAmountOut"]
    def get_amounts_in(self) -> str:
        return self._function_signatures["getAmountsIn"]
    def get_amounts_out(self) -> str:
        return self._function_signatures["getAmountsOut"]
    def quote(self) -> str:
        return self._function_signatures["quote"]
    def remove_liquidity(self) -> str:
        return self._function_signatures["removeLiquidity"]
    def remove_liquidity_eth(self) -> str:
        return self._function_signatures["removeLiquidityETH"]
    def remove_liquidity_eth_supporting_fee_on_transfer_tokens(self) -> str:
        return self._function_signatures["removeLiquidityETHSupportingFeeOnTransferTokens"]
    def remove_liquidity_eth_with_permit(self) -> str:
        return self._function_signatures["removeLiquidityETHWithPermit"]
    def remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens(self) -> str:
        return self._function_signatures["removeLiquidityETHWithPermitSupportingFeeOnTransferTokens"]
    def remove_liquidity_with_permit(self) -> str:
        return self._function_signatures["removeLiquidityWithPermit"]
    def swap_eth_for_exact_tokens(self) -> str:
        return self._function_signatures["swapETHForExactTokens"]
    def swap_exact_eth_for_tokens(self) -> str:
        return self._function_signatures["swapExactETHForTokens"]
    def swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens(self) -> str:
        return self._function_signatures["swapExactETHForTokensSupportingFeeOnTransferTokens"]
    def swap_exact_tokens_for_eth(self) -> str:
        return self._function_signatures["swapExactTokensForETH"]
    def swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens(self) -> str:
        return self._function_signatures["swapExactTokensForETHSupportingFeeOnTransferTokens"]
    def swap_exact_tokens_for_tokens(self) -> str:
        return self._function_signatures["swapExactTokensForTokens"]
    def swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens(self) -> str:
        return self._function_signatures["swapExactTokensForTokensSupportingFeeOnTransferTokens"]
    def swap_tokens_for_exact_eth(self) -> str:
        return self._function_signatures["swapTokensForExactETH"]
    def swap_tokens_for_exact_tokens(self) -> str:
        return self._function_signatures["swapTokensForExactTokens"]

# pylint: disable=too-many-public-methods,too-many-instance-attributes
class UniswapV2Router02(ContractBase):
    """Wrapper class for UniswapV2Router02 Solidity contract."""
    _fn_weth: WethMethod
    """Constructor-initialized instance of
    :class:`WethMethod`.
    """

    _fn_add_liquidity: AddLiquidityMethod
    """Constructor-initialized instance of
    :class:`AddLiquidityMethod`.
    """

    _fn_add_liquidity_eth: AddLiquidityEthMethod
    """Constructor-initialized instance of
    :class:`AddLiquidityEthMethod`.
    """

    _fn_factory: FactoryMethod
    """Constructor-initialized instance of
    :class:`FactoryMethod`.
    """

    _fn_get_amount_in: GetAmountInMethod
    """Constructor-initialized instance of
    :class:`GetAmountInMethod`.
    """

    _fn_get_amount_out: GetAmountOutMethod
    """Constructor-initialized instance of
    :class:`GetAmountOutMethod`.
    """

    _fn_get_amounts_in: GetAmountsInMethod
    """Constructor-initialized instance of
    :class:`GetAmountsInMethod`.
    """

    _fn_get_amounts_out: GetAmountsOutMethod
    """Constructor-initialized instance of
    :class:`GetAmountsOutMethod`.
    """

    _fn_quote: QuoteMethod
    """Constructor-initialized instance of
    :class:`QuoteMethod`.
    """

    _fn_remove_liquidity: RemoveLiquidityMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityMethod`.
    """

    _fn_remove_liquidity_eth: RemoveLiquidityEthMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityEthMethod`.
    """

    _fn_remove_liquidity_eth_supporting_fee_on_transfer_tokens: RemoveLiquidityEthSupportingFeeOnTransferTokensMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityEthSupportingFeeOnTransferTokensMethod`.
    """

    _fn_remove_liquidity_eth_with_permit: RemoveLiquidityEthWithPermitMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityEthWithPermitMethod`.
    """

    _fn_remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens: RemoveLiquidityEthWithPermitSupportingFeeOnTransferTokensMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityEthWithPermitSupportingFeeOnTransferTokensMethod`.
    """

    _fn_remove_liquidity_with_permit: RemoveLiquidityWithPermitMethod
    """Constructor-initialized instance of
    :class:`RemoveLiquidityWithPermitMethod`.
    """

    _fn_swap_eth_for_exact_tokens: SwapEthForExactTokensMethod
    """Constructor-initialized instance of
    :class:`SwapEthForExactTokensMethod`.
    """

    _fn_swap_exact_eth_for_tokens: SwapExactEthForTokensMethod
    """Constructor-initialized instance of
    :class:`SwapExactEthForTokensMethod`.
    """

    _fn_swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens: SwapExactEthForTokensSupportingFeeOnTransferTokensMethod
    """Constructor-initialized instance of
    :class:`SwapExactEthForTokensSupportingFeeOnTransferTokensMethod`.
    """

    _fn_swap_exact_tokens_for_eth: SwapExactTokensForEthMethod
    """Constructor-initialized instance of
    :class:`SwapExactTokensForEthMethod`.
    """

    _fn_swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens: SwapExactTokensForEthSupportingFeeOnTransferTokensMethod
    """Constructor-initialized instance of
    :class:`SwapExactTokensForEthSupportingFeeOnTransferTokensMethod`.
    """

    _fn_swap_exact_tokens_for_tokens: SwapExactTokensForTokensMethod
    """Constructor-initialized instance of
    :class:`SwapExactTokensForTokensMethod`.
    """

    _fn_swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens: SwapExactTokensForTokensSupportingFeeOnTransferTokensMethod
    """Constructor-initialized instance of
    :class:`SwapExactTokensForTokensSupportingFeeOnTransferTokensMethod`.
    """

    _fn_swap_tokens_for_exact_eth: SwapTokensForExactEthMethod
    """Constructor-initialized instance of
    :class:`SwapTokensForExactEthMethod`.
    """

    _fn_swap_tokens_for_exact_tokens: SwapTokensForExactTokensMethod
    """Constructor-initialized instance of
    :class:`SwapTokensForExactTokensMethod`.
    """

    SIGNATURES:SignatureGenerator = None

    def __init__(
        self,
        core_lib: MiliDoS,
        contract_address: str,
        validator: UniswapV2Router02Validator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = UniswapV2Router02Validator(web3, contract_address)




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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=UniswapV2Router02.abi()).functions
        signed = SignatureGenerator(UniswapV2Router02.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_weth = WethMethod(core_lib, contract_address, functions.WETH, validator)
        self._fn_add_liquidity = AddLiquidityMethod(core_lib, contract_address, functions.addLiquidity, validator)
        self._fn_add_liquidity_eth = AddLiquidityEthMethod(core_lib, contract_address, functions.addLiquidityETH, validator)
        self._fn_factory = FactoryMethod(core_lib, contract_address, functions.factory, validator)
        self._fn_get_amount_in = GetAmountInMethod(core_lib, contract_address, functions.getAmountIn, validator)
        self._fn_get_amount_out = GetAmountOutMethod(core_lib, contract_address, functions.getAmountOut, validator)
        self._fn_get_amounts_in = GetAmountsInMethod(core_lib, contract_address, functions.getAmountsIn, validator)
        self._fn_get_amounts_out = GetAmountsOutMethod(core_lib, contract_address, functions.getAmountsOut, validator)
        self._fn_quote = QuoteMethod(core_lib, contract_address, functions.quote, validator)
        self._fn_remove_liquidity = RemoveLiquidityMethod(core_lib, contract_address, functions.removeLiquidity, validator)
        self._fn_remove_liquidity_eth = RemoveLiquidityEthMethod(core_lib, contract_address, functions.removeLiquidityETH, validator)
        self._fn_remove_liquidity_eth_supporting_fee_on_transfer_tokens = RemoveLiquidityEthSupportingFeeOnTransferTokensMethod(core_lib, contract_address, functions.removeLiquidityETHSupportingFeeOnTransferTokens, validator)
        self._fn_remove_liquidity_eth_with_permit = RemoveLiquidityEthWithPermitMethod(core_lib, contract_address, functions.removeLiquidityETHWithPermit, validator)
        self._fn_remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens = RemoveLiquidityEthWithPermitSupportingFeeOnTransferTokensMethod(core_lib, contract_address, functions.removeLiquidityETHWithPermitSupportingFeeOnTransferTokens, validator)
        self._fn_remove_liquidity_with_permit = RemoveLiquidityWithPermitMethod(core_lib, contract_address, functions.removeLiquidityWithPermit, validator)
        self._fn_swap_eth_for_exact_tokens = SwapEthForExactTokensMethod(core_lib, contract_address, functions.swapETHForExactTokens, validator)
        self._fn_swap_exact_eth_for_tokens = SwapExactEthForTokensMethod(core_lib, contract_address, functions.swapExactETHForTokens, validator)
        self._fn_swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens = SwapExactEthForTokensSupportingFeeOnTransferTokensMethod(core_lib, contract_address, functions.swapExactETHForTokensSupportingFeeOnTransferTokens, validator)
        self._fn_swap_exact_tokens_for_eth = SwapExactTokensForEthMethod(core_lib, contract_address, functions.swapExactTokensForETH, validator)
        self._fn_swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens = SwapExactTokensForEthSupportingFeeOnTransferTokensMethod(core_lib, contract_address, functions.swapExactTokensForETHSupportingFeeOnTransferTokens, validator)
        self._fn_swap_exact_tokens_for_tokens = SwapExactTokensForTokensMethod(core_lib, contract_address, functions.swapExactTokensForTokens, validator)
        self._fn_swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens = SwapExactTokensForTokensSupportingFeeOnTransferTokensMethod(core_lib, contract_address, functions.swapExactTokensForTokensSupportingFeeOnTransferTokens, validator)
        self._fn_swap_tokens_for_exact_eth = SwapTokensForExactEthMethod(core_lib, contract_address, functions.swapTokensForExactETH, validator)
        self._fn_swap_tokens_for_exact_tokens = SwapTokensForExactTokensMethod(core_lib, contract_address, functions.swapTokensForExactTokens, validator)


    
    
    
    def weth(self) -> str:
        """
        Implementation of weth in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_weth.block_call()
    
    
    
    def add_liquidity(self, token_a: str, token_b: str, amount_a_desired: int, amount_b_desired: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int) -> Tuple[int, int, int]:
        """
        Implementation of add_liquidity in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_add_liquidity.block_send(token_a, token_b, amount_a_desired, amount_b_desired, amount_a_min, amount_b_min, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def add_liquidity_eth(self, token: str, amount_token_desired: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, wei:int=0) -> Tuple[int, int, int]:
        """
        Implementation of add_liquidity_eth in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
        return self._fn_add_liquidity_eth.block_send(token, amount_token_desired, amount_token_min, amount_eth_min, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,wei,self.call_contract_debug_flag,self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    def factory(self) -> str:
        """
        Implementation of factory in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_factory.block_call()
    
    
    
    def get_amount_in(self, amount_out: int, reserve_in: int, reserve_out: int) -> int:
        """
        Implementation of get_amount_in in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
        return self._fn_get_amount_in.block_call(amount_out, reserve_in, reserve_out)
    
    
    
    
    
    def get_amount_out(self, amount_in: int, reserve_in: int, reserve_out: int) -> int:
        """
        Implementation of get_amount_out in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
        return self._fn_get_amount_out.block_call(amount_in, reserve_in, reserve_out)
    
    
    
    
    
    def get_amounts_in(self, amount_out: int, path: List[str]) -> int:
        """
        Implementation of get_amounts_in in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_get_amounts_in.block_call(amount_out, path)
    
    
    
    def get_amounts_out(self, amount_in: int, path: List[str]) -> int:
        """
        Implementation of get_amounts_out in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_get_amounts_out.block_call(amount_in, path)
    
    
    
    def quote(self, amount_a: int, reserve_a: int, reserve_b: int) -> int:
        """
        Implementation of quote in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
    
        return self._fn_quote.block_call(amount_a, reserve_a, reserve_b)
    
    
    
    
    
    def remove_liquidity(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int) -> Tuple[int, int]:
        """
        Implementation of remove_liquidity in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity.block_send(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def remove_liquidity_eth(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int) -> Tuple[int, int]:
        """
        Implementation of remove_liquidity_eth in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity_eth.block_send(token, liquidity, amount_token_min, amount_eth_min, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def remove_liquidity_eth_supporting_fee_on_transfer_tokens(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int) -> int:
        """
        Implementation of remove_liquidity_eth_supporting_fee_on_transfer_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity_eth_supporting_fee_on_transfer_tokens.block_send(token, liquidity, amount_token_min, amount_eth_min, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def remove_liquidity_eth_with_permit(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> Tuple[int, int]:
        """
        Implementation of remove_liquidity_eth_with_permit in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity_eth_with_permit.block_send(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens(self, token: str, liquidity: int, amount_token_min: int, amount_eth_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> int:
        """
        Implementation of remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens.block_send(token, liquidity, amount_token_min, amount_eth_min, to, deadline, approve_max, v, r, s, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def remove_liquidity_with_permit(self, token_a: str, token_b: str, liquidity: int, amount_a_min: int, amount_b_min: int, to: str, deadline: int, approve_max: bool, v: int, r: Union[bytes, str], s: Union[bytes, str]) -> Tuple[int, int]:
        """
        Implementation of remove_liquidity_with_permit in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_remove_liquidity_with_permit.block_send(token_a, token_b, liquidity, amount_a_min, amount_b_min, to, deadline, approve_max, v, r, s, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_eth_for_exact_tokens(self, amount_out: int, path: List[str], to: str, deadline: int, wei:int=0) -> List[int]:
        """
        Implementation of swap_eth_for_exact_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
        return self._fn_swap_eth_for_exact_tokens.block_send(amount_out, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,wei,self.call_contract_debug_flag,self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    def swap_exact_eth_for_tokens(self, amount_out_min: int, path: List[str], to: str, deadline: int, wei:int=0) -> List[int]:
        """
        Implementation of swap_exact_eth_for_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
        return self._fn_swap_exact_eth_for_tokens.block_send(amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,wei,self.call_contract_debug_flag,self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    def swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens(self, amount_out_min: int, path: List[str], to: str, deadline: int, wei:int=0) -> None:
        """
        Implementation of swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
    
        return self._fn_swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens.block_send(amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,wei,self.call_contract_debug_flag,self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    def swap_exact_tokens_for_eth(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int) -> List[int]:
        """
        Implementation of swap_exact_tokens_for_eth in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_exact_tokens_for_eth.block_send(amount_in, amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int) -> None:
        """
        Implementation of swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens.block_send(amount_in, amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_exact_tokens_for_tokens(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int) -> List[int]:
        """
        Implementation of swap_exact_tokens_for_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_exact_tokens_for_tokens.block_send(amount_in, amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens(self, amount_in: int, amount_out_min: int, path: List[str], to: str, deadline: int) -> None:
        """
        Implementation of swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens.block_send(amount_in, amount_out_min, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_tokens_for_exact_eth(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int) -> List[int]:
        """
        Implementation of swap_tokens_for_exact_eth in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_tokens_for_exact_eth.block_send(amount_out, amount_in_max, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def swap_tokens_for_exact_tokens(self, amount_out: int, amount_in_max: int, path: List[str], to: str, deadline: int) -> List[int]:
        """
        Implementation of swap_tokens_for_exact_tokens in contract UniswapV2Router02
        Method of the function
    
    
    
        """
    
        return self._fn_swap_tokens_for_exact_tokens.block_send(amount_out, amount_in_max, path, to, deadline, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    

    def CallContractWait(self, t_long:int)-> "UniswapV2Router02":
        self._fn_weth.setWait(t_long)
        self._fn_add_liquidity.setWait(t_long)
        self._fn_add_liquidity_eth.setWait(t_long)
        self._fn_factory.setWait(t_long)
        self._fn_get_amount_in.setWait(t_long)
        self._fn_get_amount_out.setWait(t_long)
        self._fn_get_amounts_in.setWait(t_long)
        self._fn_get_amounts_out.setWait(t_long)
        self._fn_quote.setWait(t_long)
        self._fn_remove_liquidity.setWait(t_long)
        self._fn_remove_liquidity_eth.setWait(t_long)
        self._fn_remove_liquidity_eth_supporting_fee_on_transfer_tokens.setWait(t_long)
        self._fn_remove_liquidity_eth_with_permit.setWait(t_long)
        self._fn_remove_liquidity_eth_with_permit_supporting_fee_on_transfer_tokens.setWait(t_long)
        self._fn_remove_liquidity_with_permit.setWait(t_long)
        self._fn_swap_eth_for_exact_tokens.setWait(t_long)
        self._fn_swap_exact_eth_for_tokens.setWait(t_long)
        self._fn_swap_exact_eth_for_tokens_supporting_fee_on_transfer_tokens.setWait(t_long)
        self._fn_swap_exact_tokens_for_eth.setWait(t_long)
        self._fn_swap_exact_tokens_for_eth_supporting_fee_on_transfer_tokens.setWait(t_long)
        self._fn_swap_exact_tokens_for_tokens.setWait(t_long)
        self._fn_swap_exact_tokens_for_tokens_supporting_fee_on_transfer_tokens.setWait(t_long)
        self._fn_swap_tokens_for_exact_eth.setWait(t_long)
        self._fn_swap_tokens_for_exact_tokens.setWait(t_long)
        return self


    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"address","name":"_factory","type":"address"},{"internalType":"address","name":"_WETH","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"WETH","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"amountADesired","type":"uint256"},{"internalType":"uint256","name":"amountBDesired","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amountTokenDesired","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"factory","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountIn","outputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountOut","outputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsIn","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"reserveA","type":"uint256"},{"internalType":"uint256","name":"reserveB","type":"uint256"}],"name":"quote","outputs":[{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETHSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermit","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermitSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityWithPermit","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapETHForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETHSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]'  # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
