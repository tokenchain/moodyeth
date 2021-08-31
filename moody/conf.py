from . import Config


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
        rpc_url="https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
        chain_id=3,
        symbol="RETH",
        block_explorer="https://ropsten.etherscan.io/"
    )


def GoerliTestnet() -> Config:
    return Config(
        network_name="Goerli",
        rpc_url="https://goerli.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
        chain_id=5,
        symbol="ETH",
        block_explorer="https://goerli.etherscan.io"
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


def XDaiMainnet() -> Config:
    """
    more resources on
    https://www.xdaichain.com/for-developers/developer-resources#json-rpc-endpoints
    :return:
    """
    return Config(
        network_name="xDaiStake",
        rpc_url="https://rpc.xdaichain.com",
        # rpc_url="https://xdai.poanetwork.dev",
        # rpc_url="https://stake.getblock.io/mainnet/?api_key=bc690eca-e18a-4c53-b8e9-0f413e225e69",
        chain_id=100,
        symbol="xDai",
        block_explorer="https://explorer.anyblock.tools/ethereum/poa/xdai/",
        bridge="https://bridge.xdaichain.com/"
    )


def OKChainMainnet() -> Config:
    return Config(
        network_name="OKExChainMainnet",
        rpc_url="https://exchainrpc.okex.org",
        chain_id=66,
        symbol="OKT",
        block_explorer="https://www.oklink.com/okexchain/"
    )


def OKChainTestnet() -> Config:
    return Config(
        network_name="OKExChainTestnet",
        rpc_url="https://exchaintestrpc.okex.org",
        chain_id=65,
        symbol="OKT",
        block_explorer="https://www.oklink.com/okexchain-test/"
    )


def HSDTTestnet() -> Config:
    return Config(
        network_name="HSDTTestnet",
        rpc_url="http://47.243.141.113:12369",
        chain_id=1235,
        symbol="HSDT",
        block_explorer="http://47.243.123.252/"
    )


def HSDTMainnet() -> Config:
    return Config(
        network_name="HSDTMainnet",
        rpc_url="http://103.244.3.70:12369",
        chain_id=1236,
        symbol="HSDT",
        block_explorer="http://47.243.123.252/"
    )
