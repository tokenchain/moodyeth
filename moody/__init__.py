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
