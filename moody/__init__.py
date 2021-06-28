# Token = namedtuple('Token', ['address', 'name', 'code_hash'], defaults=(None,) * 3)
import sys
from dataclasses import dataclass

import pkg_resources

if sys.version_info < (3, 5):
    raise EnvironmentError("Python 3.5 or above is required")

# __version__ = pkg_resources.get_distribution("moodyeth").version

#__all__ = [
#    '__version__',
#]


@dataclass
class Token:
    address: str = None
    name: str = None
    code_hash: str = None
    token_contract: str = None


@dataclass
class Config:
    network_name: str
    rpc_url: str
    chain_id: int
    symbol: str
    block_explorer: str
