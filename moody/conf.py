from dataclasses import dataclass


@dataclass
class Config:
    network_name: str
    rpc_url: str
    chain_id: int
    symbol: str
    block_explorer: str


def BSCTest() -> Config:
    return Config(
        network_name="BSCTestnet",
        rpc_url="https://data-seed-prebsc-1-s1.binance.org:8545",
        chain_id=97,
        symbol="BNB",
        block_explorer="https://testnet.bscscan.com/"
    )


def BSCMain() -> Config:
    return Config(
        network_name="BinanceMainnet",
        rpc_url="https://bsc-dataseed1.binance.org",
        chain_id=56,
        symbol="BNB",
        block_explorer="https://bscscan.com"
    )


def Kovan() -> Config:
    return Config(
        network_name="Kovan",
        rpc_url="https://kovan.infura.io/v3/2019a99711c648f8951a640e8031ca33",
        chain_id=42,
        symbol="KETH",
        block_explorer="https://kovan.etherscan.io/"
    )


def Ropsten() -> Config:
    return Config(
        network_name="Ropsten",
        rpc_url="https://ropsten.infura.io/v3/2019a99711c648f8951a640e8031ca33",
        chain_id=3,
        symbol="RETH",
        block_explorer="https://ropsten.etherscan.io/"
    )


def MoonBeamTestnet() -> Config:
    return Config(
        # wss://wss.testnet.moonbeam.network
        network_name="MoonbaseAlphanet",
        rpc_url="https://rpc.testnet.moonbeam.network",
        chain_id=1287,
        symbol="DEV",
        block_explorer="https://moonbase-blockscout.testnet.moonbeam.network/"
    )


def HuobiChainMainnet() -> Config:
    return Config(
        network_name="Heco",
        rpc_url="https://http-mainnet.hecochain.com",
        chain_id=128,
        symbol="HT",
        block_explorer="https://hecoinfo.com/"
    )


def HuobiChainTestnet() -> Config:
    return Config(
        network_name="HecoTest",
        rpc_url="https://http-testnet.hecochain.com",
        chain_id=256,
        symbol="HT",
        block_explorer="https://testnet.hecoinfo.com/"
    )
