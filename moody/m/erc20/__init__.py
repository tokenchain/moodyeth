"""Generated wrapper for Ori20 Solidity contract."""

# pylint: disable=too-many-arguments

import json
from typing import (  # pylint: disable=unused-import
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
# constructor for Ori20 below.
try:
    # both mypy and pylint complain about what we're doing here, but this
    # works just fine, so their messages have been disabled here.
    from . import (  # type: ignore # pylint: disable=import-self
        Ori20Validator,
    )
except ImportError:

    class Ori20Validator(  # type: ignore
        Validator
    ):
        """No-op input validator."""

try:
    from .middleware import MIDDLEWARE  # type: ignore
except ImportError:
    pass


class AddMinterMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the addMinter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the addMinter method."""
        self.validator.assert_valid(
            method_name='addMinter',
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


class AllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the allowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, owner: str, spender: str):
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

    def block_call(self, owner: str, spender: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> int:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters



        (owner, spender) = self.validate_and_normalize_inputs(owner, spender)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(owner, spender).call(tx_params.as_dict())

        """
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

    def validate_and_normalize_inputs(self, spender: str, amount: int):
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

    def block_call(self, spender: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (spender, amount) = self.validate_and_normalize_inputs(spender, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(spender, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(spender, amount)

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

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the balanceOf method."""
        self.validator.assert_valid(
            method_name='balanceOf',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        return (account)

    def block_call(self, account: str, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> int:
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
        return int(returned)

    def estimate_gas(self, account: str, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account) = self.validate_and_normalize_inputs(account)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account).estimateGas(tx_params.as_dict())


class BurnMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the burn method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, amount: int):
        """Validate the inputs to the burn method."""
        self.validator.assert_valid(
            method_name='burn',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (amount)

    def block_call(self, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (amount) = self.validate_and_normalize_inputs(amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method(amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(amount)

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

    def send_transaction(self, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (amount) = self.validate_and_normalize_inputs(amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount).transact(tx_params.as_dict())

    def build_transaction(self, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (amount) = self.validate_and_normalize_inputs(amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (amount) = self.validate_and_normalize_inputs(amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(amount).estimateGas(tx_params.as_dict())


class BurnFromMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the burnFrom method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str, amount: int):
        """Validate the inputs to the burnFrom method."""
        self.validator.assert_valid(
            method_name='burnFrom',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        self.validator.assert_valid(
            method_name='burnFrom',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (account, amount)

    def block_call(self, account: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> None:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (account, amount) = self.validate_and_normalize_inputs(account, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        self._underlying_method(account, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(account, amount)

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

    def send_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).transact(tx_params.as_dict())

    def build_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).estimateGas(tx_params.as_dict())


class CapMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the cap method."""

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


class DecimalsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the decimals method."""

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


class DecreaseAllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the decreaseAllowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, spender: str, subtracted_value: int):
        """Validate the inputs to the decreaseAllowance method."""
        self.validator.assert_valid(
            method_name='decreaseAllowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='decreaseAllowance',
            parameter_name='subtractedValue',
            argument_value=subtracted_value,
        )
        # safeguard against fractional inputs
        subtracted_value = int(subtracted_value)
        return (spender, subtracted_value)

    def block_call(self, spender: str, subtracted_value: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(spender, subtracted_value).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(spender, subtracted_value)

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

    def send_transaction(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, subtracted_value: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, subtracted_value) = self.validate_and_normalize_inputs(spender, subtracted_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, subtracted_value).estimateGas(tx_params.as_dict())


class GetDecimalsMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the getDecimals method."""

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


class IncreaseAllowanceMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the increaseAllowance method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, spender: str, added_value: int):
        """Validate the inputs to the increaseAllowance method."""
        self.validator.assert_valid(
            method_name='increaseAllowance',
            parameter_name='spender',
            argument_value=spender,
        )
        spender = self.validate_and_checksum_address(spender)
        self.validator.assert_valid(
            method_name='increaseAllowance',
            parameter_name='addedValue',
            argument_value=added_value,
        )
        # safeguard against fractional inputs
        added_value = int(added_value)
        return (spender, added_value)

    def block_call(self, spender: str, added_value: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(spender, added_value).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(spender, added_value)

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

    def send_transaction(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).transact(tx_params.as_dict())

    def build_transaction(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, spender: str, added_value: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (spender, added_value) = self.validate_and_normalize_inputs(spender, added_value)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(spender, added_value).estimateGas(tx_params.as_dict())


class IsMinterMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the isMinter method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str):
        """Validate the inputs to the isMinter method."""
        self.validator.assert_valid(
            method_name='isMinter',
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


class MintMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the mint method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, account: str, amount: int):
        """Validate the inputs to the mint method."""
        self.validator.assert_valid(
            method_name='mint',
            parameter_name='account',
            argument_value=account,
        )
        account = self.validate_and_checksum_address(account)
        self.validator.assert_valid(
            method_name='mint',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (account, amount)

    def block_call(self, account: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (account, amount) = self.validate_and_normalize_inputs(account, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(account, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(account, amount)

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

    def send_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).transact(tx_params.as_dict())

    def build_transaction(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, account: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (account, amount) = self.validate_and_normalize_inputs(account, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(account, amount).estimateGas(tx_params.as_dict())


class NameMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the name method."""

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


class RenounceMinterMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the renounceMinter method."""

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


class SymbolMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the symbol method."""

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


class TokenNameMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tokenName method."""

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


class TokenSymbolMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the tokenSymbol method."""

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


class TotalSupplyMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the totalSupply method."""

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


class TransferMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transfer method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, recipient: str, amount: int):
        """Validate the inputs to the transfer method."""
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='recipient',
            argument_value=recipient,
        )
        recipient = self.validate_and_checksum_address(recipient)
        self.validator.assert_valid(
            method_name='transfer',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (recipient, amount)

    def block_call(self, recipient: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (recipient, amount) = self.validate_and_normalize_inputs(recipient, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(recipient, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(recipient, amount)

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


class TransferFromMethod(ContractMethod):  # pylint: disable=invalid-name
    """Various interfaces to the transferFrom method."""

    def __init__(self, elib: MiliDoS, contract_address: str, contract_function: ContractFunction, validator: Validator = None):
        """Persist instance data."""
        super().__init__(elib, contract_address, validator)
        self._underlying_method = contract_function

    def validate_and_normalize_inputs(self, sender: str, recipient: str, amount: int):
        """Validate the inputs to the transferFrom method."""
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='sender',
            argument_value=sender,
        )
        sender = self.validate_and_checksum_address(sender)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='recipient',
            argument_value=recipient,
        )
        recipient = self.validate_and_checksum_address(recipient)
        self.validator.assert_valid(
            method_name='transferFrom',
            parameter_name='amount',
            argument_value=amount,
        )
        # safeguard against fractional inputs
        amount = int(amount)
        return (sender, recipient, amount)

    def block_call(self, sender: str, recipient: str, amount: int, val: int = 0, fee: int = 1000000, debug: bool = False, enforcereci: bool = False) -> bool:
        """Execute underlying contract method via eth_call.

        :param tx_params: transaction parameters
        :returns: the return value of the underlying method.


        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)

        tx_params: Optional[TxParams] = None
        tx_params = super().normalize_tx_params(tx_params)

        returned = self._underlying_method(sender, recipient, amount).call(tx_params.as_dict())

        """
        _fn = self._underlying_method(sender, recipient, amount)

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

    def send_transaction(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> Union[HexBytes, bytes]:
        """Execute underlying contract method via eth_sendTransaction.

        :param tx_params: transaction parameters
        """
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).transact(tx_params.as_dict())

    def build_transaction(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> dict:
        """Construct calldata to be used as input to the method."""
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).buildTransaction(tx_params.as_dict())

    def estimate_gas(self, sender: str, recipient: str, amount: int, tx_params: Optional[TxParams] = None) -> int:
        """Estimate gas consumption of method call."""
        (sender, recipient, amount) = self.validate_and_normalize_inputs(sender, recipient, amount)
        tx_params = super().normalize_tx_params(tx_params)
        return self._underlying_method(sender, recipient, amount).estimateGas(tx_params.as_dict())


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class Ori20:
    """Wrapper class for Ori20 Solidity contract."""
    _fn_add_minter: AddMinterMethod
    """Constructor-initialized instance of
    :class:`AddMinterMethod`.
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

    _fn_burn: BurnMethod
    """Constructor-initialized instance of
    :class:`BurnMethod`.
    """

    _fn_burn_from: BurnFromMethod
    """Constructor-initialized instance of
    :class:`BurnFromMethod`.
    """

    _fn_cap: CapMethod
    """Constructor-initialized instance of
    :class:`CapMethod`.
    """

    _fn_decimals: DecimalsMethod
    """Constructor-initialized instance of
    :class:`DecimalsMethod`.
    """

    _fn_decrease_allowance: DecreaseAllowanceMethod
    """Constructor-initialized instance of
    :class:`DecreaseAllowanceMethod`.
    """

    _fn_get_decimals: GetDecimalsMethod
    """Constructor-initialized instance of
    :class:`GetDecimalsMethod`.
    """

    _fn_increase_allowance: IncreaseAllowanceMethod
    """Constructor-initialized instance of
    :class:`IncreaseAllowanceMethod`.
    """

    _fn_is_minter: IsMinterMethod
    """Constructor-initialized instance of
    :class:`IsMinterMethod`.
    """

    _fn_mint: MintMethod
    """Constructor-initialized instance of
    :class:`MintMethod`.
    """

    _fn_name: NameMethod
    """Constructor-initialized instance of
    :class:`NameMethod`.
    """

    _fn_renounce_minter: RenounceMinterMethod
    """Constructor-initialized instance of
    :class:`RenounceMinterMethod`.
    """

    _fn_symbol: SymbolMethod
    """Constructor-initialized instance of
    :class:`SymbolMethod`.
    """

    _fn_token_name: TokenNameMethod
    """Constructor-initialized instance of
    :class:`TokenNameMethod`.
    """

    _fn_token_symbol: TokenSymbolMethod
    """Constructor-initialized instance of
    :class:`TokenSymbolMethod`.
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

    def __init__(
            self,
            core_lib: MiliDoS,
            contract_address: str,
            validator: Ori20Validator = None,
    ):
        """Get an instance of wrapper for smart contract.
        """
        # pylint: disable=too-many-statements

        self.contract_address = contract_address
        web3 = core_lib.w3

        if not validator:
            validator = Ori20Validator(web3, contract_address)

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

        functions = self._web3_eth.contract(address=to_checksum_address(contract_address), abi=Ori20.abi()).functions

        self.call_contract_fee_amount: int = 100000000000000000
        self.call_contract_debug_flag: bool = False
        self.call_contract_enforce_tx_receipt: bool = False

        self._fn_add_minter = AddMinterMethod(core_lib, contract_address, functions.addMinter, validator)

        self._fn_allowance = AllowanceMethod(core_lib, contract_address, functions.allowance, validator)

        self._fn_approve = ApproveMethod(core_lib, contract_address, functions.approve, validator)

        self._fn_balance_of = BalanceOfMethod(core_lib, contract_address, functions.balanceOf, validator)

        self._fn_burn = BurnMethod(core_lib, contract_address, functions.burn, validator)

        self._fn_burn_from = BurnFromMethod(core_lib, contract_address, functions.burnFrom, validator)

        self._fn_cap = CapMethod(core_lib, contract_address, functions.cap)

        self._fn_decimals = DecimalsMethod(core_lib, contract_address, functions.decimals)

        self._fn_decrease_allowance = DecreaseAllowanceMethod(core_lib, contract_address, functions.decreaseAllowance, validator)

        self._fn_get_decimals = GetDecimalsMethod(core_lib, contract_address, functions.getDecimals)

        self._fn_increase_allowance = IncreaseAllowanceMethod(core_lib, contract_address, functions.increaseAllowance, validator)

        self._fn_is_minter = IsMinterMethod(core_lib, contract_address, functions.isMinter, validator)

        self._fn_mint = MintMethod(core_lib, contract_address, functions.mint, validator)

        self._fn_name = NameMethod(core_lib, contract_address, functions.name)

        self._fn_renounce_minter = RenounceMinterMethod(core_lib, contract_address, functions.renounceMinter)

        self._fn_symbol = SymbolMethod(core_lib, contract_address, functions.symbol)

        self._fn_token_name = TokenNameMethod(core_lib, contract_address, functions.tokenName)

        self._fn_token_symbol = TokenSymbolMethod(core_lib, contract_address, functions.tokenSymbol)

        self._fn_total_supply = TotalSupplyMethod(core_lib, contract_address, functions.totalSupply)

        self._fn_transfer = TransferMethod(core_lib, contract_address, functions.transfer, validator)

        self._fn_transfer_from = TransferFromMethod(core_lib, contract_address, functions.transferFrom, validator)

    def event_approval(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event approval in contract Ori20
        Get log entry for Approval event.
                :param tx_hash: hash of transaction emitting Approval event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Ori20.abi()).events.Approval().processReceipt(tx_receipt)

    def event_minter_added(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event minter_added in contract Ori20
        Get log entry for MinterAdded event.
                :param tx_hash: hash of transaction emitting MinterAdded event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Ori20.abi()).events.MinterAdded().processReceipt(tx_receipt)

    def event_minter_removed(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event minter_removed in contract Ori20
        Get log entry for MinterRemoved event.
                :param tx_hash: hash of transaction emitting MinterRemoved event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Ori20.abi()).events.MinterRemoved().processReceipt(tx_receipt)

    def event_transfer(
            self, tx_hash: Union[HexBytes, bytes]
    ) -> Tuple[AttributeDict]:
        """
        Implementation of event transfer in contract Ori20
        Get log entry for Transfer event.
                :param tx_hash: hash of transaction emitting Transfer event
        """
        tx_receipt = self._web3_eth.getTransactionReceipt(tx_hash)
        return self._web3_eth.contract(address=to_checksum_address(self.contract_address), abi=Ori20.abi()).events.Transfer().processReceipt(tx_receipt)

    def add_minter(self, account: str) -> None:
        """
        Implementation of add_minter in contract Ori20

        """
        return self._fn_add_minter.block_call(account, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def allowance(self, owner: str, spender: str) -> int:
        """
        Implementation of allowance in contract Ori20

        """
        return self._fn_allowance.block_call(owner, spender)

    def approve(self, spender: str, amount: int) -> bool:
        """
        Implementation of approve in contract Ori20

        """
        return self._fn_approve.block_call(spender, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def balance_of(self, account: str) -> int:
        """
        Implementation of balance_of in contract Ori20

        """
        return self._fn_balance_of.block_call(account)

    def burn(self, amount: int) -> None:
        """
        Implementation of burn in contract Ori20

        """
        return self._fn_burn.block_call(amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def burn_from(self, account: str, amount: int) -> None:
        """
        Implementation of burn_from in contract Ori20

        """
        return self._fn_burn_from.block_call(account, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def cap(self) -> int:
        """
        Implementation of cap in contract Ori20

        """
        return self._fn_cap.block_call()

    def decimals(self) -> int:
        """
        Implementation of decimals in contract Ori20

        """
        return self._fn_decimals.block_call()

    def decrease_allowance(self, spender: str, subtracted_value: int) -> bool:
        """
        Implementation of decrease_allowance in contract Ori20

        """
        return self._fn_decrease_allowance.block_call(spender, subtracted_value, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def get_decimals(self) -> int:
        """
        Implementation of get_decimals in contract Ori20

        """
        return self._fn_get_decimals.block_call()

    def increase_allowance(self, spender: str, added_value: int) -> bool:
        """
        Implementation of increase_allowance in contract Ori20

        """
        return self._fn_increase_allowance.block_call(spender, added_value, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def is_minter(self, account: str) -> bool:
        """
        Implementation of is_minter in contract Ori20

        """
        return self._fn_is_minter.block_call(account)

    def mint(self, account: str, amount: int) -> bool:
        """
        Implementation of mint in contract Ori20

        """
        return self._fn_mint.block_call(account, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def name(self) -> str:
        """
        Implementation of name in contract Ori20

        """
        return self._fn_name.block_call()

    def renounce_minter(self) -> None:
        """
        Implementation of renounce_minter in contract Ori20

        """
        return self._fn_renounce_minter.block_call(0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def symbol(self) -> str:
        """
        Implementation of symbol in contract Ori20

        """
        return self._fn_symbol.block_call()

    def token_name(self) -> str:
        """
        Implementation of token_name in contract Ori20

        """
        return self._fn_token_name.block_call()

    def token_symbol(self) -> str:
        """
        Implementation of token_symbol in contract Ori20

        """
        return self._fn_token_symbol.block_call()

    def total_supply(self) -> int:
        """
        Implementation of total_supply in contract Ori20

        """
        return self._fn_total_supply.block_call()

    def transfer(self, recipient: str, amount: int) -> bool:
        """
        Implementation of transfer in contract Ori20

        """
        return self._fn_transfer.block_call(recipient, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def transfer_from(self, sender: str, recipient: str, amount: int) -> bool:
        """
        Implementation of transfer_from in contract Ori20

        """
        return self._fn_transfer_from.block_call(sender, recipient, amount, 0, self.call_contract_fee_amount, self.call_contract_debug_flag, self.call_contract_enforce_tx_receipt)

    def CallContractFee(self, amount: int) -> "Ori20":
        self.call_contract_fee_amount = amount
        return self

    def CallDebug(self, yesno: bool) -> "Ori20":
        self.call_contract_debug_flag = yesno
        return self

    def EnforceTxReceipt(self, yesno: bool) -> "Ori20":
        self.call_contract_enforce_tx_receipt = yesno
        return self

    @staticmethod
    def abi():
        """Return the ABI to the underlying contract."""
        return json.loads(
            '[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"}],"name":"MinterAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"}],"name":"MinterRemoved","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"addMinter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"burn","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"burnFrom","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"cap","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"getDecimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isMinter","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"mint","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"renounceMinter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"tokenName","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"tokenSymbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
            # noqa: E501 (line-too-long)
        )

# pylint: disable=too-many-lines
