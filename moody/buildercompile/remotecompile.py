from moody.paths import Paths
from . import REC, ITEM, ITEMLINK


def compileItem1(tar: Paths, k0: str) -> str:
    """
    list the item content
    :param tar:
    :param k0:
    :return:
    """
    return ITEM.format(
        SOLCPATH=tar.SOLCPATH,
        COMPILE_COIN=k0,
        SOLVER=tar.SOLC_VER,
        EVMVERSION=str(tar.EVM_VERSION)
    )


def compileItem2(tar: Paths, k0: str, link_lib_conf: str) -> str:
    """

    :param tar:
    :param k0:
    :param link:
    :return:
    """

    return ITEMLINK.format(
        SOLCPATH=tar.SOLCPATH,
        COMPILE_COIN=k0,
        FILES_CONFIG=link_lib_conf,
        SOLVER=tar.SOLC_VER,
    )


def wrapContent(tar: Paths, compile_list: list) -> str:
    """
    wrap content
    :param tar:
    :param compile_list:
    :return:
    """
    return REC.format(
        LISTP="\n".join(compile_list),
        TARGET_LOC=tar.TARGET_LOC,
        COMPRESSED_NAME=tar.COMPRESSED_NAME,
        SOLVER=tar.SOLC_VER,
    )


def BuildRemoteLinuxCommand(p: Paths, list_files: list = None, linked: dict = None) -> None:
    """
    building the remote linux command line
    :param p:
    :param list_files:
    :return:
    """
    k = list()
    # ==================================================
    if list_files is not None:
        for v in list_files:
            k.append(compileItem1(p, v))
    # ==================================================
    if linked is not None:
        for c in linked:
            if "compile" in c and "libraries" in c:
                compile_file = c["compile"]
                lib_cmds = list()
                """
                solc before v0.8.1
                
                example: link = {
                    "filepath.sol:CLASS:0x0930193019391093012930209099302129"
                }
                
                solc --optimize --bin MetaCoin.sol | solc --link --libraries TestLib:<address>
                
                """
                for b in c["libraries"]:
                    if "class" in b and "address" in b:
                        source_line = "{}:{}".format(b["class"], b["address"])
                        if "src" in b:
                            source_line = "{}:{}:{}".format(b["src"], b["class"], b["address"])
                        lib_cmds.append(source_line)
                library_link_cmd = " ".join(lib_cmds)
                k.append(compileItem2(p, compile_file, library_link_cmd))
    # ==================================================
    with open(p.workspaceFilename("remotesolc"), 'w') as f:
        f.write(wrapContent(p, k))
        f.close()
    # ==================================================
