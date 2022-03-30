"""Generated wrapper for BlockhashStore Solidity contract."""

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
# constructor for BlockhashStore below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        BlockhashStoreValidator,
    )
except ImportError:

    class BlockhashStoreValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass





class GetBlockhashMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the getBlockhash method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("getBlockhash")

    def validate_and_normalize_inputs(self, n: int)->any:
        """Validate the inputs to the getBlockhash method."""
        self.validator.assert_valid(
            method_name='getBlockhash',
            parameter_name='n',
            argument_value=n,
        )
        # safeguard against fractional inputs
        n = int(n)
        return (n)



    def block_call(self,n: int, debug:bool=False) -> Union[bytes, str]:
        _fn = self._underlying_method(n)
        returned = _fn.call({
                'from': self._operate
            })
        return Union[bytes, str](returned)
    def block_send(self, n: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> Union[bytes, str]:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(n)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: get_blockhash")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")


    def send_transaction(self, n: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).transact(tx_params.as_dict())

    def build_transaction(self, n: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, n: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).estimateGas(tx_params.as_dict())

class StoreMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the store method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("store")

    def validate_and_normalize_inputs(self, n: int)->any:
        """Validate the inputs to the store method."""
        self.validator.assert_valid(
            method_name='store',
            parameter_name='n',
            argument_value=n,
        )
        # safeguard against fractional inputs
        n = int(n)
        return (n)



    def block_send(self, n: int,_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(n)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: store")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")


    def send_transaction(self, n: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).transact(tx_params.as_dict())

    def build_transaction(self, n: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, n: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (n) = self.validate_and_normalize_inputs(n)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n).estimateGas(tx_params.as_dict())

class StoreEarliestMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the storeEarliest method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("storeEarliest")



    def block_send(self, _gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: store_earliest")

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

class StoreVerifyHeaderMethod(ContractMethod): # pylint: disable=invalid-name
    """Various interfaces to the storeVerifyHeader method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator=None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function
        self.sign = validator.getSignature("storeVerifyHeader")

    def validate_and_normalize_inputs(self, n: int, header: Union[bytes, str])->any:
        """Validate the inputs to the storeVerifyHeader method."""
        self.validator.assert_valid(
            method_name='storeVerifyHeader',
            parameter_name='n',
            argument_value=n,
        )
        # safeguard against fractional inputs
        n = int(n)
        self.validator.assert_valid(
            method_name='storeVerifyHeader',
            parameter_name='header',
            argument_value=header,
        )
        return (n, header)



    def block_send(self, n: int, header: Union[bytes, str],_gaswei:int,_pricewei:int,_valeth:int=0,_debugtx: bool = False,_receipList: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.
        """
        _fn = self._underlying_method(n, header)
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
            print(f"{Bolors.FAIL}Error {er} {Bolors.RESET}: store_verify_header")

        except ValueError as err:
            if "message" in err.args[0]:
                message = err.args[0]["message"]
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET} on set_asset_token: {message}")
            else:
                print(f"{Bolors.FAIL}Error Revert {Bolors.RESET}: set_asset_token")


    def send_transaction(self, n: int, header: Union[bytes, str], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (n, header) = self.validate_and_normalize_inputs(n, header)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n, header).transact(tx_params.as_dict())

    def build_transaction(self, n: int, header: Union[bytes, str], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (n, header) = self.validate_and_normalize_inputs(n, header)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n, header).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, n: int, header: Union[bytes, str], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (n, header) = self.validate_and_normalize_inputs(n, header)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(n, header).estimateGas(tx_params.as_dict())

class SignatureGenerator(Signatures):
    """
        The signature is generated for this and it is installed.
    """
    def __init__(self, abi: any):
        super().__init__(abi)

    def get_blockhash(self) -> str:
        return self._function_signatures["getBlockhash"]
    def store(self) -> str:
        return self._function_signatures["store"]
    def store_earliest(self) -> str:
        return self._function_signatures["storeEarliest"]
    def store_verify_header(self) -> str:
        return self._function_signatures["storeVerifyHeader"]

# pylint: disable=too-many-public-methods,too-many-instance-attributes
class BlockhashStore(ContractBase):
    """Wrapper class for BlockhashStore Solidity contract.

    All method parameters of type `bytes`:code: should be encoded as UTF-8,
    which can be accomplished via `str.encode("utf_8")`:code:.
    """
    _fn_get_blockhash: GetBlockhashMethod
    """Constructor-initialized instance of
    :class:`GetBlockhashMethod`.
    """

    _fn_store: StoreMethod
    """Constructor-initialized instance of
    :class:`StoreMethod`.
    """

    _fn_store_earliest: StoreEarliestMethod
    """Constructor-initialized instance of
    :class:`StoreEarliestMethod`.
    """

    _fn_store_verify_header: StoreVerifyHeaderMethod
    """Constructor-initialized instance of
    :class:`StoreVerifyHeaderMethod`.
    """

    SIGNATURES:SignatureGenerator = None

    def __init__(
        self,
        core_lib: MiliDoS,
        contract_address: str,
        validator: BlockhashStoreValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements
        super().__init__()
        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = BlockhashStoreValidator(web3, contract_address)




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
        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=BlockhashStore.abi()).functions
        signed = SignatureGenerator(BlockhashStore.abi())
        validator.bindSignatures(signed)
        self.SIGNATURES = signed
        self._fn_get_blockhash = GetBlockhashMethod(core_lib, contract_address, functions.getBlockhash, validator)
        self._fn_store = StoreMethod(core_lib, contract_address, functions.store, validator)
        self._fn_store_earliest = StoreEarliestMethod(core_lib, contract_address, functions.storeEarliest, validator)
        self._fn_store_verify_header = StoreVerifyHeaderMethod(core_lib, contract_address, functions.storeVerifyHeader, validator)


    
    
    
    def get_blockhash(self, n: int) -> Union[bytes, str]:
        """
        Implementation of get_blockhash in contract BlockhashStore
        Method of the function
    
    
    
        """
    
    
    
    
    
        return self._fn_get_blockhash.block_call(n)
    
    
    
    def store(self, n: int) -> None:
        """
        Implementation of store in contract BlockhashStore
        Method of the function
    
    
    
        """
    
        return self._fn_store.block_send(n, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def store_earliest(self) -> None:
        """
        Implementation of store_earliest in contract BlockhashStore
        Method of the function
    
    
    
        """
    
        return self._fn_store_earliest.block_send(self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    
    
    
    
    def store_verify_header(self, n: int, header: Union[bytes, str]) -> None:
        """
        Implementation of store_verify_header in contract BlockhashStore
        Method of the function
    
    
    
        """
    
        return self._fn_store_verify_header.block_send(n, header, self.call_contract_fee_amount,self.call_contract_fee_price,0,self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)
    
    
    
    

    def CallContractWait(self, t_long:int)-> "BlockhashStore":
        self._fn_get_blockhash.setWait(t_long)
        self._fn_store.setWait(t_long)
        self._fn_store_earliest.setWait(t_long)
        self._fn_store_verify_header.setWait(t_long)
        return self


    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[{"internalType":"uint256","name":"n","type":"uint256"}],"name":"getBlockhash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"n","type":"uint256"}],"name":"store","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"storeEarliest","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"n","type":"uint256"},{"internalType":"bytes","name":"header","type":"bytes"}],"name":"storeVerifyHeader","outputs":[],"stateMutability":"nonpayable","type":"function"}]'  # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
