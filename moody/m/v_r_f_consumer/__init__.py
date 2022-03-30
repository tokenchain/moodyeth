"""Generated wrapper for VRFConsumer Solidity contract."""

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
# constructor for VRFConsumer below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        VRFConsumerValidator,
    )
except ImportError:

    class VRFConsumerValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass





class GetRandomNumberMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getRandomNumber method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getRandomNumber")



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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_random_number")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_random_number: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, get_random_number. Reason: Unknown")


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

class RandomResultMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the randomResult method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("randomResult")



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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: random_result")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, random_result: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, random_result. Reason: Unknown")


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

class RawFulfillRandomnessMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the rawFulfillRandomness method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("rawFulfillRandomness")

    def validate_and_normalize_inputs(self, request_id: Union[bytes, str], randomness: int)->any:
        """Validate the inputs to the rawFulfillRandomness method."""
        self.validator.assert_valid(
            method_name='rawFulfillRandomness',
            parameter_name='requestId',
            argument_value=request_id,
        )
        self.validator.assert_valid(
            method_name='rawFulfillRandomness',
            parameter_name='randomness',
            argument_value=randomness,
        )
        # safeguard against fractional inputs
        randomness = int(randomness)
        return (request_id, randomness)



    def block_send(self, request_id: Union[bytes, str], randomness: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(request_id, randomness)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: raw_fulfill_randomness")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, raw_fulfill_randomness: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}, raw_fulfill_randomness. Reason: Unknown")


    def send_transaction(self, request_id: Union[bytes, str], randomness: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (request_id, randomness) = self.validate_and_normalize_inputs(request_id, randomness)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, randomness).transact(tx_params.as_dict())

    def build_transaction(self, request_id: Union[bytes, str], randomness: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (request_id, randomness) = self.validate_and_normalize_inputs(request_id, randomness)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, randomness).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, request_id: Union[bytes, str], randomness: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (request_id, randomness) = self.validate_and_normalize_inputs(request_id, randomness)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(request_id, randomness).estimateGas(tx_params.as_dict())

class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """
    def __init__(self, abi: any):
        super().__init__(abi)

    def get_random_number(self) -> str:
        return self._function_signatures["getRandomNumber"]
    def random_result(self) -> str:
        return self._function_signatures["randomResult"]
    def raw_fulfill_randomness(self) -> str:
        return self._function_signatures["rawFulfillRandomness"]

# pylint: disable=too-many-public-methods,too-many-instance-attributes
class VRFConsumer(ContractBase):
    """Wrapper class for VRFConsumer Solidity contract."""
    _fn_get_random_number: GetRandomNumberMethod
    """Constructor-initialized instance of
    :class:`GetRandomNumberMethod`.
    """

    _fn_random_result: RandomResultMethod
    """Constructor-initialized instance of
    :class:`RandomResultMethod`.
    """

    _fn_raw_fulfill_randomness: RawFulfillRandomnessMethod
    """Constructor-initialized instance of
    :class:`RawFulfillRandomnessMethod`.
    """

    SIGNATURES:SignatureGenerator = None

    def __init__(
        self,
        core_lib: MiliDoS,
        contract_address: str,
        validator: VRFConsumerValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = VRFConsumerValidator(web3, contract_address)




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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=VRFConsumer.abi()).functions
        signed = SignatureGenerator(VRFConsumer.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_get_random_number = GetRandomNumberMethod(core_lib, contract_address, functions.getRandomNumber, validator)
        self._fn_random_result = RandomResultMethod(core_lib, contract_address, functions.randomResult, validator)
        self._fn_raw_fulfill_randomness = RawFulfillRandomnessMethod(core_lib, contract_address, functions.rawFulfillRandomness, validator)

    
    
    def event_random_number_arrived(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event random_number_arrived in contract VRFConsumer
        Get log entry for randomNumberArrived event.
                :param tx_hash: hash of transaction emitting randomNumberArrived event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=VRFConsumer.abi()).events.randomNumberArrived().processReceipt(tx_receipt)

    
    
    
    def get_random_number(self) -> Union[bytes, str]:
        """
        Implementation of get_random_number in contract VRFConsumer
        Method of the function
    
    
    
        """
    
        return self._fn_get_random_number.block_send(self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def random_result(self) -> int:
        """
        Implementation of random_result in contract VRFConsumer
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_random_result.block_call()
    
    
    
    def raw_fulfill_randomness(self, request_id: Union[bytes, str], randomness: int) -> None:
        """
        Implementation of raw_fulfill_randomness in contract VRFConsumer
        Method of the function
    
    
    
        """
    
        return self._fn_raw_fulfill_randomness.block_send(request_id, randomness, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    

    def CallContractWait(self, t_long:int)-> "VRFConsumer":
        self._fn_get_random_number.setWait(t_long)
        self._fn_random_result.setWait(t_long)
        self._fn_raw_fulfill_randomness.setWait(t_long)
        return self


    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"bool","name":"arrived","type":"bool"},{"indexed":false,"internalType":"uint256","name":"randomNumber","type":"uint256"},{"indexed":false,"internalType":"bytes32","name":"batchID","type":"bytes32"}],"name":"randomNumberArrived","type":"event"},{"inputs":[],"name":"getRandomNumber","outputs":[{"internalType":"bytes32","name":"requestId","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"randomResult","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"requestId","type":"bytes32"},{"internalType":"uint256","name":"randomness","type":"uint256"}],"name":"rawFulfillRandomness","outputs":[],"stateMutability":"nonpayable","type":"function"}]'  # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
