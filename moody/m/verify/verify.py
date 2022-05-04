import os
from subprocess import CalledProcessError

from moody.libeb import MiliDoS, SolWeb3Tool
from moody import Config
from .solfla import SolflatlinerWrapper
from ..verify.http import HttpProvider


def verifyInternalSource(
        network: Config,
        rootpath: str,
        sourceClassName: str,
        original_source_file_entry: str,
):
    """
    we will enable this by the network
    :param network:
    :param rootpath:
    :param sourceClassName:
    :param original_source_file_entry:
    :return:
    """
    maker = SolflatlinerWrapper(rootpath)

    meta = MiliDoS(network).withPOA()
    meta.setWorkspace(rootpath).Auth()

    if meta.hasContractName(sourceClassName) is False:
        print(f"There is no contract for {sourceClassName} found.")
        exit(2)

    solcf = SolWeb3Tool()
    solcf.setBasePath(rootpath)
    solcf.setBuildNameSpace("artifacts")
    solcf.LoadInternalMeta(sourceClassName)
    print(f"open root path is {rootpath}")
    input_source = os.path.join(rootpath, original_source_file_entry)
    try:
        maker.make_flaten_tmp_file(input_source, solcf.GetMetaCompilerVer(False))
    except CalledProcessError:
        print("Error from calling the verification from merging source file")

    if maker.proccess_result is False:
        print(f"Failed to make the merge source file from {input_source}")
        exit(44)

    _sendVerifyRequest(
        explorer_base_uri=network.block_explorer,
        contractAddress=meta.getAddr(sourceClassName),
        solidity_ver=solcf.GetMetaSettings().solidity_ver,
        mergedSource=solcf.ReadAsStrAndEscape(maker.output_file),
        optimizationUsed=solcf.GetMetaSettings().optimization_enabled,
        optimzationRuns=solcf.GetMetaSettings().optimization_runs,
        encodedConstructorArgs=[],
        contractName=sourceClassName
    )


# source code pasting not sure how to do it
# https://github.com/eth-brownie/brownie/blob/ce603c59b5e4cd46de0782e969214af3e796a7d7/brownie/project/ethpm.py#L92

def verifyBySource(
        network: Config,
        rootpath: str,
        sourceClassName: str,
        original_source_file_entry: str
):
    """
    sol flatliner wrapper
    :param network:
    :param rootpath:
    :param sourceClassName:
    :param original_source_file_entry:
    :return:
    """
    maker = SolflatlinerWrapper(rootpath)
    meta = MiliDoS(network).withPOA()
    meta.setWorkspace(rootpath).Auth()
    if meta.hasContractName(sourceClassName) is False:
        print(f"There is no contract for {sourceClassName} found.")
        exit(2)

    solcf = SolWeb3Tool()
    solcf.setBasePath(rootpath)
    solcf.GetCodeClassFromBuild(sourceClassName)
    input_source = os.path.join(rootpath, original_source_file_entry)
    try:
        maker.make_flaten_tmp_file(input_source, solcf.GetMetaCompilerVer(False))
    except CalledProcessError:
        print("Error from calling the verification from merging source file")

    if maker.proccess_result is False:
        print(f"Failed to make the merge source file from {input_source}")
        exit(44)

    _sendVerifyRequest(
        explorer_base_uri=network.block_explorer,
        contractAddress=meta.getAddr(sourceClassName),
        solidity_ver=solcf.GetMetaSettings().solidity_ver_full,
        mergedSource=solcf.ReadAsStrAndEscape(maker.output_file),
        optimizationUsed=solcf.GetMetaSettings().optimization_enabled,
        optimzationRuns=solcf.GetMetaSettings().optimization_runs,
        encodedConstructorArgs=[],
        contractName=sourceClassName
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

    o = HttpProvider()
    pre = dict(
        addressHash=contractAddress,
        contractSourceCode=mergedSource,
        name=contractName,
        compilerVersion=f"v{solidity_ver}",
        optimization=optimizationUsed,
        optimizationRuns=optimzationRuns,
        constructorArguments=encodedConstructorArgs
    )
    print(pre)
    result = o.request(verifyapi, json=pre, method="POST")
    print(result)
