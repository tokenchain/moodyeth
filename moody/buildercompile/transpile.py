import os
import re

from moody.paths import Paths
from . import ITEM_CP_LOCAL, TRANS_LOCAL, ITEM_TRANSPILE_PYTHON, ITEM_TRANSPILE_TS

REG = r"(.+?)([A-Z])"


def snake(match):
    return match.group(1).lower() + "_" + match.group(2).lower()


def filter_file_name(y: str) -> str:
    classNameNew = y
    if y.startswith("TRC"):
        classNameNew = y.lower()
    elif y.startswith("ERC20"):
        classNameNew = y.upper()
    else:
        classNameNew = re.sub(REG, snake, y, 0)
    print(classNameNew)
    return classNameNew


def buildCmdTsUpdate(p: Paths, pathName: str) -> str:
    nameClass = filter_file_name(os.path.basename(pathName)).replace('.sol', '')
    fromp = "{}/codec/gen_ts/{}.ts".format(p.BUILDPATH, nameClass)
    top = "{}/{}/src/api/abi/{}.ts".format(p.BUILDPATH, p.WEB_DAPP_SRC, nameClass)
    return ITEM_CP_LOCAL.format(
        fromlocation=fromp,
        tolocation=top
    )


def buildCmdPy(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_PYTHON.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_py",
        target_abi=f"{p.BUILDPATH}/build/{os.path.basename(pathName).replace('.sol', '')}.abi",
        BUILDPATH=p.BUILDPATH
    )


def buildCmdTs(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_TS.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_ts",
        target_abi=f"{p.BUILDPATH}/build/{os.path.basename(pathName).replace('.sol', '')}.abi",
        BUILDPATH=p.BUILDPATH
    )


def wrapContent(tar: Paths, compile_list: list) -> str:
    """
    wrap content
    :param tar:
    :param compile_list:
    :return:
    """
    return TRANS_LOCAL.format(
        LISTP="\n".join(compile_list),
        TARGET_LOC=tar.TARGET_LOC,
        COMPRESSED_NAME=tar.COMPRESSED_NAME,
        SOLVER=tar.SOLC_VER,
    )


def BuildLang(p: Paths, list_class_names: list) -> None:
    """

    :param p:
    :param list_class_names:
    :return:
    """
    k = list()
    # ==================================================
    for v in list_class_names:
        k.append(buildCmdPy(p, v))
        k.append(buildCmdTs(p, v))
        k.append(buildCmdTsUpdate(p, v))
    # ==================================================
    with open(p.workspaceFilename("localpile"), 'w') as f:
        f.write(wrapContent(p, k))
        f.close()
