# Token = namedtuple('Token', ['address', 'name', 'code_hash'], defaults=(None,) * 3)
from dataclasses import dataclass


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
