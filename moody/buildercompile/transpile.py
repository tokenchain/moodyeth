import os
import re

from ..paths import Paths
from . import ITEM_CP_LOCAL, ITEM_TRANSPILE_GO, TRANS_LOCAL, ITEM_TRANSPILE_PYTHON, ITEM_TRANSPILE_TS, PRE_HEAD, SUB_FOOTER

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


def moveTsFiles(p: Paths, pathName: str) -> str:
    nameClass = filter_file_name(os.path.basename(pathName)).replace('.sol', '')
    fromp = "{}/codec/gen_ts/{}.ts".format(p.BUILDPATH, nameClass)
    top = "{}/{}/src/api/abi/{}.ts".format(p.BUILDPATH, p.WEB_DAPP_SRC, nameClass)
    return ITEM_CP_LOCAL.format(
        fromlocation=fromp,
        tolocation=top
    )


def abiPath_v1(p: Paths, pathName: str) -> str:
    return f"{p.BUILDPATH}/build/{os.path.basename(pathName).replace('.sol', '')}.abi"


def abiPath_v2(p: Paths, pathName: str) -> str:
    file_name = os.path.basename(pathName)
    return f"{p.BUILDPATH}/build/{file_name}/{file_name.replace('.sol', '')}.abi"


def buildCmdPy(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_PYTHON.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_py",
        target_abi=abiPath_v1(p, pathName),
        BUILDPATH=p.BUILDPATH
    )


def buildCmdPy2(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_PYTHON.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_py",
        target_abi=abiPath_v2(p, pathName),
        BUILDPATH=p.BUILDPATH
    )


def buildCmdTs(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_TS.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_ts",
        target_abi=abiPath_v1(p, pathName),
        BUILDPATH=p.BUILDPATH
    )


def buildCmdTs2(p: Paths, pathName: str) -> str:
    return ITEM_TRANSPILE_TS.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_ts",
        target_abi=abiPath_v2(p, pathName),
        BUILDPATH=p.BUILDPATH
    )


def buildCmdGo(p: Paths, pathName: str) -> str:
    based_name = os.path.basename(pathName)
    class_name = filter_file_name(based_name).replace('.sol', '')
    return ITEM_TRANSPILE_GO.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_go",
        target_abi=abiPath_v1(p, pathName),
        BUILDPATH=p.BUILDPATH,
        classname=class_name
    )


def buildCmdGo2(p: Paths, pathName: str) -> str:
    based_name = os.path.basename(pathName)
    class_name = filter_file_name(based_name).replace('.sol', '')
    return ITEM_TRANSPILE_GO.format(
        outputfolder=f"{p.BUILDPATH}/codec/gen_go",
        target_abi=abiPath_v2(p, pathName),
        BUILDPATH=p.BUILDPATH,
        classname=class_name
    )


def wrapContentTranspile(tar: Paths, compile_list: list) -> str:
    """
    wrap content
    :param tar: path in string
    :param compile_list: the list in compile
    :return:
    """
    head_section = PRE_HEAD.format(path_definitions=tar.LOCAL_BASH_INCLUDE)
    contract_list_content = "\n".join(compile_list)
    return TRANS_LOCAL.format(
        TARGET_LOC=tar.TARGET_LOC,
        COMPRESSED_NAME=tar.COMPRESSED_NAME,
        SOLVER=tar.SOLC_VER,
        LISTP=contract_list_content,
        PRE_HEAD=head_section,
        FOOTER=SUB_FOOTER
    )


def BuildLang(p: Paths, list_class_names: list) -> None:
    """

    :param p: path in string
    :param list_class_names: the class name
    :return:
    """
    k = list()
    # ==================================================
    for v in list_class_names:
        k.append(buildCmdPy(p, v))
        k.append(buildCmdTs(p, v))
        k.append(buildCmdGo(p, v))
        if p.WEB_DAPP_SRC is not None:
            k.append(moveTsFiles(p, v))
    # ==================================================
    with open(p.workspaceFilename("localpile"), 'w') as f:
        f.write(wrapContentTranspile(p, k))
        f.close()


def BuildLangForge(p: Paths, list_class_names: list) -> None:
    """

    :param p: path in string
    :param list_class_names: the class name
    :return:
    """
    k = list()
    # ==================================================
    for v in list_class_names:
        k.append(buildCmdPy2(p, v))
        k.append(buildCmdTs2(p, v))
        k.append(buildCmdGo2(p, v))
        if p.WEB_DAPP_SRC is not None:
            k.append(moveTsFiles(p, v))
    # ==================================================
    with open(p.workspaceFilename("localpile"), 'w') as f:
        f.write(wrapContentTranspile(p, k))
        f.close()
