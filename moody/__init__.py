# Token = namedtuple('Token', ['address', 'name', 'code_hash'], defaults=(None,) * 3)
import os
import sys
from dataclasses import dataclass

import pkg_resources

if sys.version_info < (3, 5):
    raise EnvironmentError("Python 3.5 or above is required")

__version__ = pkg_resources.get_distribution("moodyeth").version


# __all__ = [
#    '__version__',
# ]


@dataclass
class Token:
    address: str = None
    name: str = None
    code_hash: str = None
    token_contract: str = None
    decimal: int = 0
    total_supply: int = 0
    spender: dict = None
    balance: dict = None


@dataclass
class Config:
    network_name: str
    rpc_url: str
    chain_id: int
    symbol: str
    block_explorer: str
    bridge: str = "",
    faucet: str = "",
    gas: int = 6000000,
    gasPrice: int = 1059100000
    one: int = 1000000000000000000
    wait_time: int = 6,
    # Oracle from Chainlink
    # https://docs.chain.link/docs/vrf-contracts/
    link_token: str = None,
    link_vrf_coordinator: str = None
    link_keyhash: str = None


@dataclass
class Key:
    private_key: str
    wallet_address: str
    token: str
    precision: int
    network: str


class Bolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR


# EVM history: https://en.wikipedia.org/wiki/Ethereum
class Evm:
    TANGERINEWHISTLE = "tangerineWhistle"
    """
    18 October 2016
    Gas cost for access to other accounts increased, relevant for gas estimation and the optimizer.
    All gas sent by default for external calls, previously a certain amount had to be retained.
    """
    SPURIOUSDRAGON = "spuriousDragon"
    """
    23 November 2016
    Gas cost for the exp opcode increased, relevant for gas estimation and the optimizer.
    """
    BYZANTIUM = "byzantium"
    """
    16 October 2017
    Opcodes `returndatacopy`, `returndatasize` and `staticcall` are available in assembly.
    The `staticcall` opcode is used when calling non-library view or pure functions, which prevents the functions from modifying state at the EVM level, i.e., even applies when you use invalid type conversions.
    It is possible to access dynamic data returned from function calls.
    revert opcode introduced, which means that `revert()` will not waste gas.
    """
    CONSTANTINOPLE = "constantinople"
    """
    28 February 2019
    Opcodes `create2`, `extcodehash`, `shl`, `shr` and `sar` are available in assembly.
    Shifting operators use shifting opcodes and thus need less gas.
    """
    PETERSBURG = "petersburg"
    """
    28 February 2019
    The compiler behaves the same way as with constantinople.
    """
    ISTANBUL = "istanbul"
    """
    8 December 2019
    Opcodes `chainid` and `selfbalance` are available in assembly.
    """
    BERLIN = "berlin"
    """
    15 April 2021
    Gas costs for `SLOAD`, `*CALL`, `BALANCE`, `EXT*` and `SELFDESTRUCT` increased. The compiler assumes cold gas costs for such operations. This is relevant for gas estimation and the optimizer.
    """
    LONDON = "london"
    """
    5 August 2021
    The block’s base fee (EIP-3198 and EIP-1559) can be accessed via the global block.basefee or basefee() in inline assembly.
    """


class DefaultKeys:
    k0 = "000000000000000000000000000000000000000000000000000000000000001e"


root_base_path = os.path.join(os.path.dirname(__file__))

__all__ = [
    '__version__',
    'Evm',
    'Config',
    'Bolors',
    'DefaultKeys',
    'root_base_path'
]
