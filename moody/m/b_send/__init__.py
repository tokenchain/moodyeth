"""Generated wrapper for BSend Solidity contract."""

# pylint: disable=too-many-arguments

import json
from typing import (  # pylint: disable=unused-import
    List,
    Optional,
    Tuple,
    Union,
)

from eth_utils import to_checksum_address
from hexbytes import HexBytes
from web3.contract import ContractFunction
from web3.datastructures import AttributeDict

from ..bases import ContractMethod, Validator
from ..tx_params import TxParams
from ...libeb import MiliDoS

# Try to import a custom validator class definition; if there isn't one,
# declare one that we can instantiate for the default argument to the
# constructor for BSend below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        BSendValidator,
    )
except ImportError:

    class BSendValidator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AddWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the addWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='addWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (account) = self.validate_and_normalize_inputs(account)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method(account).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(account)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class BulkSendTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the bulkSendToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, token_addr: str, addresses: List[str], amounts: List[int]):
        """Validate the inputs to the bulkSendToken method."""
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='tokenAddr',
            argument_value=token_addr,
        )
        token_addr = self.validate_and_checksum_address(token_addr)
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='addresses',
            argument_value=addresses,
        )
        self.validator.assert_valid(
            method_name='bulkSendToken',
            parameter_name='amounts',
            argument_value=amounts,
        )
        return (token_addr, addresses, amounts)

    def block_call(self, token_addr: str, addresses: List[str], amounts: List[int], val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(token_addr, addresses, amounts).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(token_addr, addresses, amounts)

        _t = _fn.buildTransaction({
            'from': self._operate
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
            print(f"===>> enforcement is {enforcereci}")

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")
        return False

    def send_transaction(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).transact(tx_params.as_dict())

    def build_transaction(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_addr: str, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_addr, addresses, amounts) = self.validate_and_normalize_inputs(token_addr, addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, addresses, amounts).estimateGas(tx_params.as_dict())


class BulkSendTrxMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the bulkSendTrx method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, addresses: List[str], amounts: List[int]):
        """Validate the inputs to the bulkSendTrx method."""
        self.validator.assert_valid(
            method_name='bulkSendTrx',
            parameter_name='addresses',
            argument_value=addresses,
        )
        self.validator.assert_valid(
            method_name='bulkSendTrx',
            parameter_name='amounts',
            argument_value=amounts,
        )
        return (addresses, amounts)

    def block_call(self, addresses: List[str], amounts: List[int], val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(addresses, amounts).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(addresses, amounts)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

    def send_transaction(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).transact(tx_params.as_dict())

    def build_transaction(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, addresses: List[str], amounts: List[int], tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addresses, amounts) = self.validate_and_normalize_inputs(addresses, amounts)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addresses, amounts).estimateGas(tx_params.as_dict())


class DepositMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the deposit method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.



        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class EthSendFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the ethSendFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters




        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class GetbalanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getbalance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, addr: str):
        """Validate the inputs to the getbalance method."""
        self.validator.assert_valid(
            method_name='getbalance',
            parameter_name='addr',
            argument_value=addr,
        )
        addr = self.validate_and_checksum_address(addr)
        return (addr)

    def block_call(self, addr: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters



        (addr) = self.validate_and_normalize_inputs(addr)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(addr).call(tx_params.as_dict())

        """
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


class IsLockedMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isLocked method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters




        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class IsOwnerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isOwner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters




        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class IsWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the isWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='isWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters



        (account) = self.validate_and_normalize_inputs(account)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(account).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(account)

        returned = _fn.call({
            'from': self._operate
        })
        return bool(returned)

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class OwnerMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the owner method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> str:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters




        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        returned = _fn.call({
            'from': self._operate
        })
        return str(returned)

    def estimate_gas(self, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method().estimateGas(tx_params.as_dict())


class PulllockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the pulllock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.



        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class RemoveWhitelistAdminMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the removeWhitelistAdmin method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the removeWhitelistAdmin method."""
        self.validator.assert_valid(
            method_name='removeWhitelistAdmin',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (account) = self.validate_and_normalize_inputs(account)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method(account).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(account)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class RenounceOwnershipMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the renounceOwnership method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.



        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class SetEthFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setEthFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, eth_send_fee: int):
        """Validate the inputs to the setEthFee method."""
        self.validator.assert_valid(
            method_name='setEthFee',
            parameter_name='_ethSendFee',
            argument_value=eth_send_fee,
        )
        # safeguard against fractional inputs
        eth_send_fee = int(eth_send_fee)
        return (eth_send_fee)

    def block_call(self, eth_send_fee: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(eth_send_fee).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(eth_send_fee)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

    def send_transaction(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).transact(tx_params.as_dict())

    def build_transaction(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, eth_send_fee: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (eth_send_fee) = self.validate_and_normalize_inputs(eth_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(eth_send_fee).estimateGas(tx_params.as_dict())


class SetTokenFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the setTokenFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, token_send_fee: int):
        """Validate the inputs to the setTokenFee method."""
        self.validator.assert_valid(
            method_name='setTokenFee',
            parameter_name='_tokenSendFee',
            argument_value=token_send_fee,
        )
        # safeguard against fractional inputs
        token_send_fee = int(token_send_fee)
        return (token_send_fee)

    def block_call(self, token_send_fee: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(token_send_fee).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(token_send_fee)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

    def send_transaction(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).transact(tx_params.as_dict())

    def build_transaction(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_send_fee: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_send_fee) = self.validate_and_normalize_inputs(token_send_fee)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_send_fee).estimateGas(tx_params.as_dict())


class TokenSendFeeMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tokenSendFee method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters




        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        returned = _fn.call({
            'from': self._operate
        })
        return int(returned)

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

    def validate_and_normalize_inputs(self, new_owner: str):
        """Validate the inputs to the transferOwnership method."""
        self.validator.assert_valid(
            method_name='transferOwnership',
            parameter_name='newOwner',
            argument_value=new_owner,
        )
        new_owner = self.validate_and_checksum_address(new_owner)
        return (new_owner)

    def block_call(self, new_owner: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (new_owner) = self.validate_and_normalize_inputs(new_owner)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method(new_owner).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(new_owner)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class UnlockMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the unlock method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction):
        """Persist instance data."""
        super().__init__(elib, contract_address)
        self._underlying_method = contract_function

    def block_call(self, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.



        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method().call(tx_params.as_dict())

        """
        _fn = self._underlying_method()

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

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


class WithdrawEtherMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdrawEther method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, addr: str, amount: int):
        """Validate the inputs to the withdrawEther method."""
        self.validator.assert_valid(
            method_name='withdrawEther',
            parameter_name='addr',
            argument_value=addr,
        )
        addr = self.validate_and_checksum_address(addr)
        self.validator.assert_valid(
            method_name='withdrawEther',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (addr, amount)

    def block_call(self, addr: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(addr, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(addr, amount)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

    def send_transaction(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).transact(tx_params.as_dict())

    def build_transaction(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, addr: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (addr, amount) = self.validate_and_normalize_inputs(addr, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(addr, amount).estimateGas(tx_params.as_dict())


class WithdrawTokenMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the withdrawToken method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, token_addr: str, to: str, amount: int):
        """Validate the inputs to the withdrawToken method."""
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='tokenAddr',
            argument_value=token_addr,
        )
        token_addr = self.validate_and_checksum_address(token_addr)
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='_to',
            argument_value=to,
        )
        to = self.validate_and_checksum_address(to)
        self.validator.assert_valid(
            method_name='withdrawToken',
            parameter_name='_amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (token_addr, to, amount)

    def block_call(self, token_addr: str, to: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(token_addr, to, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(token_addr, to, amount)

        _t = _fn.buildTransaction({
            'from': self._operate
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

            if enforcereci is True:
                print("======== Wait for confirmation 🚸️")
                tx_receipt = self._web3_eth.waitForTransactionReceipt(txHash)
                print("======== TX Result ✅")
                print(tx_receipt)
                if debug:
                    print(f"======== TX blockHash ✅ {tx_receipt.blockHash}")

    def send_transaction(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).transact(tx_params.as_dict())

    def build_transaction(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, token_addr: str, to: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (token_addr, to, amount) = self.validate_and_normalize_inputs(token_addr, to, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(token_addr, to, amount).estimateGas(tx_params.as_dict())


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class BSend:
    """Wrapper class for BSend Solidity contract."""
    _fn_add_whitelist_admin: AddWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`AddWhitelistAdminMethod`.
    """

    _fn_bulk_send_token: BulkSendTokenMethod
    """Constructor-initialized instance of
    :class:`BulkSendTokenMethod`.
    """

    _fn_bulk_send_trx: BulkSendTrxMethod
    """Constructor-initialized instance of
    :class:`BulkSendTrxMethod`.
    """

    _fn_deposit: DepositMethod
    """Constructor-initialized instance of
    :class:`DepositMethod`.
    """

    _fn_eth_send_fee: EthSendFeeMethod
    """Constructor-initialized instance of
    :class:`EthSendFeeMethod`.
    """

    _fn_getbalance: GetbalanceMethod
    """Constructor-initialized instance of
    :class:`GetbalanceMethod`.
    """

    _fn_is_locked: IsLockedMethod
    """Constructor-initialized instance of
    :class:`IsLockedMethod`.
    """

    _fn_is_owner: IsOwnerMethod
    """Constructor-initialized instance of
    :class:`IsOwnerMethod`.
    """

    _fn_is_whitelist_admin: IsWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`IsWhitelistAdminMethod`.
    """

    _fn_owner: OwnerMethod
    """Constructor-initialized instance of
    :class:`OwnerMethod`.
    """

    _fn_pulllock: PulllockMethod
    """Constructor-initialized instance of
    :class:`PulllockMethod`.
    """

    _fn_remove_whitelist_admin: RemoveWhitelistAdminMethod
    """Constructor-initialized instance of
    :class:`RemoveWhitelistAdminMethod`.
    """

    _fn_renounce_ownership: RenounceOwnershipMethod
    """Constructor-initialized instance of
    :class:`RenounceOwnershipMethod`.
    """

    _fn_set_eth_fee: SetEthFeeMethod
    """Constructor-initialized instance of
    :class:`SetEthFeeMethod`.
    """

    _fn_set_token_fee: SetTokenFeeMethod
    """Constructor-initialized instance of
    :class:`SetTokenFeeMethod`.
    """

    _fn_token_send_fee: TokenSendFeeMethod
    """Constructor-initialized instance of
    :class:`TokenSendFeeMethod`.
    """

    _fn_transfer_ownership: TransferOwnershipMethod
    """Constructor-initialized instance of
    :class:`TransferOwnershipMethod`.
    """

    _fn_unlock: UnlockMethod
    """Constructor-initialized instance of
    :class:`UnlockMethod`.
    """

    _fn_withdraw_ether: WithdrawEtherMethod
    """Constructor-initialized instance of
    :class:`WithdrawEtherMethod`.
    """

    _fn_withdraw_token: WithdrawTokenMethod
    """Constructor-initialized instance of
    :class:`WithdrawTokenMethod`.
    """

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: BSendValidator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements

        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = BSendValidator(web3, contract_address)

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

        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=BSend.abi()).functions

        self.call_contract_fee_amount: int = 100000000000000000
        self.call_contract_debug_flag: bool = False
        self.call_contract_enforce_tx_receipt: bool = False

        self._fn_add_whitelist_admin = AddWhitelistAdminMethod(core_lib, contract_address, functions.addWhitelistAdmin, validator)

        self._fn_bulk_send_token = BulkSendTokenMethod(core_lib, contract_address, functions.bulkSendToken, validator)

        self._fn_bulk_send_trx = BulkSendTrxMethod(core_lib, contract_address, functions.bulkSendTrx, validator)

        self._fn_deposit = DepositMethod(core_lib, contract_address, functions.deposit)

        self._fn_eth_send_fee = EthSendFeeMethod(core_lib, contract_address, functions.ethSendFee)

        self._fn_getbalance = GetbalanceMethod(core_lib, contract_address, functions.getbalance, validator)

        self._fn_is_locked = IsLockedMethod(core_lib, contract_address, functions.isLocked)

        self._fn_is_owner = IsOwnerMethod(core_lib, contract_address, functions.isOwner)

        self._fn_is_whitelist_admin = IsWhitelistAdminMethod(core_lib, contract_address, functions.isWhitelistAdmin, validator)

        self._fn_owner = OwnerMethod(core_lib, contract_address, functions.owner)

        self._fn_pulllock = PulllockMethod(core_lib, contract_address, functions.pulllock)

        self._fn_remove_whitelist_admin = RemoveWhitelistAdminMethod(core_lib, contract_address, functions.removeWhitelistAdmin, validator)

        self._fn_renounce_ownership = RenounceOwnershipMethod(core_lib, contract_address, functions.renounceOwnership)

        self._fn_set_eth_fee = SetEthFeeMethod(core_lib, contract_address, functions.setEthFee, validator)

        self._fn_set_token_fee = SetTokenFeeMethod(core_lib, contract_address, functions.setTokenFee, validator)

        self._fn_token_send_fee = TokenSendFeeMethod(core_lib, contract_address, functions.tokenSendFee)

        self._fn_transfer_ownership = TransferOwnershipMethod(core_lib, contract_address, functions.transferOwnership, validator)

        self._fn_unlock = UnlockMethod(core_lib, contract_address, functions.unlock)

        self._fn_withdraw_ether = WithdrawEtherMethod(core_lib, contract_address, functions.withdrawEther, validator)

        self._fn_withdraw_token = WithdrawTokenMethod(core_lib, contract_address, functions.withdrawToken, validator)

    def event_ownership_transferred(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event ownership_transferred in contract BSend
        Get log entry for OwnershipTransferred event.
                :param tx_hash: hash of transaction emitting OwnershipTransferred event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend.abi()).events.OwnershipTransferred().processReceipt(tx_receipt)

    def event_traillock(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event traillock in contract BSend
        Get log entry for traillock event.
                :param tx_hash: hash of transaction emitting traillock event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=BSend.abi()).events.traillock().processReceipt(tx_receipt)

    def add_whitelist_admin(self, account: str) -> None:
        """
        Implementation of add_whitelist_admin in contract BSend

        """
        return self._fn_add_whitelist_admin.block_call(account, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def bulk_send_token(self, token_addr: str, addresses: List[str], amounts: List[int], trx: int = 0) -> bool:
        """
        Implementation of bulk_send_token in contract BSend

        """
        return self._fn_bulk_send_token.block_call(token_addr, addresses, amounts, trx, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def bulk_send_trx(self, addresses: List[str], amounts: List[int], trx: int = 0) -> bool:
        """
        Implementation of bulk_send_trx in contract BSend

        """
        return self._fn_bulk_send_trx.block_call(addresses, amounts, trx, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def deposit(self, trx: int = 0) -> bool:
        """
        Implementation of deposit in contract BSend

        """
        return self._fn_deposit.block_call(trx, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def eth_send_fee(self) -> int:
        """
        Implementation of eth_send_fee in contract BSend

        """
        return self._fn_eth_send_fee.block_call()

    def getbalance(self, addr: str) -> int:
        """
        Implementation of getbalance in contract BSend

        """
        return self._fn_getbalance.block_call(addr)

    def is_locked(self) -> bool:
        """
        Implementation of is_locked in contract BSend

        """
        return self._fn_is_locked.block_call()

    def is_owner(self) -> bool:
        """
        Implementation of is_owner in contract BSend

        """
        return self._fn_is_owner.block_call()

    def is_whitelist_admin(self, account: str) -> bool:
        """
        Implementation of is_whitelist_admin in contract BSend

        """
        return self._fn_is_whitelist_admin.block_call(account)

    def owner(self) -> str:
        """
        Implementation of owner in contract BSend

        """
        return self._fn_owner.block_call()

    def pulllock(self) -> None:
        """
        Implementation of pulllock in contract BSend

        """
        return self._fn_pulllock.block_call(0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def remove_whitelist_admin(self, account: str) -> None:
        """
        Implementation of remove_whitelist_admin in contract BSend

        """
        return self._fn_remove_whitelist_admin.block_call(account, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def renounce_ownership(self) -> None:
        """
        Implementation of renounce_ownership in contract BSend

        """
        return self._fn_renounce_ownership.block_call(0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_eth_fee(self, eth_send_fee: int) -> bool:
        """
        Implementation of set_eth_fee in contract BSend

        """
        return self._fn_set_eth_fee.block_call(eth_send_fee, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def set_token_fee(self, token_send_fee: int) -> bool:
        """
        Implementation of set_token_fee in contract BSend

        """
        return self._fn_set_token_fee.block_call(token_send_fee, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def token_send_fee(self) -> int:
        """
        Implementation of token_send_fee in contract BSend

        """
        return self._fn_token_send_fee.block_call()

    def transfer_ownership(self, new_owner: str) -> None:
        """
        Implementation of transfer_ownership in contract BSend

        """
        return self._fn_transfer_ownership.block_call(new_owner, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def unlock(self) -> None:
        """
        Implementation of unlock in contract BSend

        """
        return self._fn_unlock.block_call(0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def withdraw_ether(self, addr: str, amount: int) -> bool:
        """
        Implementation of withdraw_ether in contract BSend

        """
        return self._fn_withdraw_ether.block_call(addr, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def withdraw_token(self, token_addr: str, to: str, amount: int) -> bool:
        """
        Implementation of withdraw_token in contract BSend

        """
        return self._fn_withdraw_token.block_call(token_addr, to, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def CallContractFee(self, amount: int) -> "BSend":
        self.call_contract_fee_amount = amount
        return self

    def CallDebug(self, yesno: bool) -> "BSend":
        self.call_contract_debug_flag = yesno
        return self

    def EnforceTxReceipt(self, yesno: bool) -> "BSend":
        self.call_contract_enforce_tx_receipt = yesno
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"payable":true,"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint8","name":"value","type":"uint8"}],"name":"traillock","type":"event"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"addWhitelistAdmin","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"internalType":"address[]","name":"addresses","type":"address[]"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"bulkSendTrx","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[],"name":"ethSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"getbalance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"isLocked","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"isOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isWhitelistAdmin","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"pulllock","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"removeWhitelistAdmin","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"renounceOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_ethSendFee","type":"uint256"}],"name":"setEthFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_tokenSendFee","type":"uint256"}],"name":"setTokenFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"tokenSendFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"unlock","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"addr","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdrawEther","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"tokenAddr","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdrawToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
