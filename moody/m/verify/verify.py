from moody.libeb import MiliDoS, SolWeb3Tool
from moody import Config
from ..verify.http import HttpProvider


def bySource(network: Config, rootpath: str, sourceClassName: str, filename: str):
    meta = MiliDoS(network).withPOA()
    meta.setWorkspace(rootpath).Auth()
    if meta.hasContractName(sourceClassName) is False:
        print(f"There is no contract for {sourceClassName} found.")
        exit(2)

    solc_artifact = SolWeb3Tool()
    solc_artifact.setBasePath(rootpath)
    solc_artifact = solc_artifact.GetCodeClassFromBuild(sourceClassName)

    _sendVerifyRequest(
        explorer_base_uri=network.block_explorer,
        contractAddress=meta.getAddr(sourceClassName),
        solidity_ver=solc_artifact.GetMetaCompilerVer(),
        mergedSource=solc_artifact.GetSourceFileRead(f"vault/{filename}.sol"),
        optimizationUsed=True,
        optimzationRuns=10000,
        encodedConstructorArgs=[]
    )


def _sendVerifyRequest(explorer_base_uri: str,
                       contractAddress: str,
                       mergedSource: str,
                       contractName: str,
                       optimizationUsed: bool,
                       optimzationRuns: int,
                       solidity_ver: str,
                       encodedConstructorArgs: list,
                       ):
    apiuri = f"{explorer_base_uri}/api"
    verifyapi = f"{apiuri}?module=contract&action=verify"

    # todo: maybe there are links for the lib

    o = HttpProvider("")
    result = o.request(verifyapi, dict(
        addressHash=contractAddress,
        contractSourceCode=mergedSource,
        name=contractName,
        compilerVersion=f"v{solidity_ver}",
        optimization=optimizationUsed,
        optimizationRuns=optimzationRuns,
        constructorArguments=encodedConstructorArgs
    ))

    print(result)
