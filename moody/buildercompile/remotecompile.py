from moody.paths import Paths
from . import REC, ITEM


def listItemContent(tar: Paths, k0: str) -> str:
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


def BuildRemoteLinuxCommand(p: Paths, list_files: list) -> None:
    """
    building the remote linux command line
    :param p:
    :param list_files:
    :return:
    """
    k = list()
    # ==================================================
    for v in list_files:
        k.append(listItemContent(p, v))
    # ==================================================
    with open(p.workspaceFilename("remotesolc"), 'w') as f:
        f.write(wrapContent(p, k))
        f.close()
