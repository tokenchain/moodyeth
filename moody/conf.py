from . import Config


def BSCTest() -> Config:
    return Config(
        network_name="BSCTestnet",
        rpc_url="https://data-seed-prebsc-1-s1.binance.org:8545",
        chain_id=97,
        symbol="BNB",
        block_explorer="https://testnet.bscscan.com/",
        link_token="0x84b9B910527Ad5C03A9Ca831909E21e236EA7b06",
        link_vrf_coordinator="0xa555fC018435bef5A13C6c6870a9d4C11DEC329C",
        link_keyhash="0xcaf3c3727e033261d383b315559476f48034c13b18f8cafed4d871abe5049186"
    )


def BSCMain() -> Config:
    return Config(
        network_name="BinanceMainnet",
        rpc_url="https://bsc-dataseed1.binance.org",
        chain_id=56,
        symbol="BNB",
        block_explorer="https://bscscan.com",
        link_token="0x404460C6A5EdE2D891e8297795264fDe62ADBB75",
        link_keyhash="0xc251acd21ec4fb7f31bb8868288bfdbaeb4fbfec2df3735ddbd4f7dc8d60103c",
        link_vrf_coordinator="0x747973a5A2a4Ae1D3a8fDF5479f1514F65Db9C31"
    )


def PolygonMumbai() -> Config:
    return Config(
        network_name="PolygonMumbaiTestnet",
        rpc_url="https://bsc-dataseed1.binance.org",
        chain_id=56,
        symbol="BNB",
        block_explorer="https://bscscan.com",
        link_token="0x326C977E6efc84E512bB9C30f76E30c160eD06FB",
        link_keyhash="0x6e75b569a01ef56d18cab6a8e71e6600d6ce853834d4a5748b720d06f878b3a4",
        link_vrf_coordinator="0x8C7382F9D8f56b33781fE506E897a4F1e2d17255"
    )


def PolygonMainnet() -> Config:
    return Config(
        network_name="PolygonMainnet",
        rpc_url="https://bsc-dataseed1.binance.org",
        chain_id=56,
        symbol="BNB",
        block_explorer="https://bscscan.com",
        link_token="0xb0897686c545045aFc77CF20eC7A532E3120E0F1",
        link_keyhash="0xf86195cf7690c55907b2b611ebb7343a6f649bff128701cc542f0569e2c549da",
        link_vrf_coordinator="0x3d2341ADb2D31f1c5530cDC622016af293177AE0"
    )


def Kovan() -> Config:
    return Config(
        network_name="Kovan",
        rpc_url="https://kovan.infura.io/v3/2019a99711c648f8951a640e8031ca33",
        chain_id=42,
        symbol="KETH",
        block_explorer="https://kovan.etherscan.io/",
        link_token="0xa36085F69e2889c224210F603D836748e7dC0088",
        link_vrf_coordinator="0xdD3782915140c8f3b190B5D67eAc6dc5760C46E9",
        link_keyhash="0x6c3699283bda56ad74f6b855546325b68d482e983852a7a82979cc4807b641f4"
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


def RSCTestnet() -> Config:
    return Config(
        network_name="RSCTestnet",
        rpc_url="http://47.243.141.113:12369",
        chain_id=1235,
        symbol="RSCT",
        block_explorer="http://47.243.123.252/"
    )


def RSCMainnet() -> Config:
    return Config(
        network_name="RSCMainnet",
        rpc_url="http://103.244.3.70:12369",
        chain_id=1236,
        symbol="RSCT",
        block_explorer="http://47.243.123.252/"
    )
