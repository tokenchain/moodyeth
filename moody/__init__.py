# Token = namedtuple('Token', ['address', 'name', 'code_hash'], defaults=(None,) * 3)
import sys
from dataclasses import dataclass

if sys.version_info < (3, 5):
    raise EnvironmentError("Python 3.5 or above is required")


# __version__ = pkg_resources.get_distribution("moodyeth").version

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


from enum import Enum


class Evm(Enum):
    TANGERINEWHISTLE = "tangerineWhistle"
    """
    Gas cost for access to other accounts increased, relevant for gas estimation and the optimizer.
    All gas sent by default for external calls, previously a certain amount had to be retained.
    """
    SPURIOUSDRAGON = "spuriousDragon"
    """
    Gas cost for the exp opcode increased, relevant for gas estimation and the optimizer.
    """
    BYZANTIUM = "byzantium"
    """
    Opcodes `returndatacopy`, `returndatasize` and `staticcall` are available in assembly.
    The `staticcall` opcode is used when calling non-library view or pure functions, which prevents the functions from modifying state at the EVM level, i.e., even applies when you use invalid type conversions.
    It is possible to access dynamic data returned from function calls.
    revert opcode introduced, which means that `revert()` will not waste gas.
    """
    CONSTANTINOPLE = "constantinople"
    """
    Opcodes `create2`, `extcodehash`, `shl`, `shr` and `sar` are available in assembly.
    Shifting operators use shifting opcodes and thus need less gas.
    """
    PETERSBURG = "petersburg"
    """
    The compiler behaves the same way as with constantinople.
    """
    ISTANBUL = "istanbul"
    """
    Opcodes `chainid` and `selfbalance` are available in assembly.
    """
    BERLIN = "berlin"
    """
    Gas costs for `SLOAD`, `*CALL`, `BALANCE`, `EXT*` and `SELFDESTRUCT` increased. The compiler assumes cold gas costs for such operations. This is relevant for gas estimation and the optimizer.
    """
    LONDON = "london"
    """
    The block’s base fee (EIP-3198 and EIP-1559) can be accessed via the global block.basefee or basefee() in inline assembly.
    """
