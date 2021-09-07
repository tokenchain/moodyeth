#!/usr/bin/env python
"""Base wrapper class for accessing ethereum smart contracts."""
import codecs
import json
import os


# from datetime import datetime
# from typing import Any, Union, Tuple


class Paths:
    """
    :type statement
    Manage the workspace paths

    """
    statement = 'End : {}, IO File {}'
    _contract_dict: dict
    _network: str
    FILE_CONTRACT = "backedup"
    ACTION_FOLDER = "deploy_results"
    HISTORY_FOLDER = "deploy_history"
    COLLECTION_CONTRACTS = "players"
    DEPLOYMENT_FILE_NAME = "deploy_{}{}.json"
    VERSION_NAME = "v{}"
    NAME_FILE_EXX = "{}/{}.json"
    # ---- sovernior
    TARGET_LOC = "/root/contracts"
    COMPRESSED_NAME = "solc-build.tar.gz"
    SOLC_VER = "0.5.15"
    SOLCPATH = "/root/contracts/vault"
    BUILDPATH = ""
    WEB_DAPP_SRC = "app"

    def __init__(self, root_path_as_workspace):
        self.___workspace = root_path_as_workspace
        self.___current_deployment_path = os.path.join(self.___workspace, self.ACTION_FOLDER)
        self.SUB_FIX = ""
        self.___network_name = "mainnet"
        self.BUILDPATH = root_path_as_workspace

    @property
    def subFix(self) -> str:
        """preview the file name"""
        return self.SUB_FIX

    @subFix.setter
    def subFix(self, sub: str) -> "Paths":
        """the file name does not require extension name"""
        self.SUB_FIX = sub
        return self

    @classmethod
    def showCurrentDeployedClass(cls, class_name: str) -> str:
        return cls.NAME_FILE_EXX.format(cls.ACTION_FOLDER, class_name)

    def updateTargetDappFolder(self, folderName: str) -> "Paths":
        self.WEB_DAPP_SRC = folderName
        return self

    def setSolVersion(self, version: str) -> "Paths":
        self.SOLC_VER = version
        return self

    def setDefaultPath(self) -> "Paths":
        self.___current_deployment_path = os.path.join(self.___workspace, self.ACTION_FOLDER)
        return self

    def workspaceFilename(self, name) -> str:
        return os.path.join(self.___workspace, name)

    def classObject(self, className: str) -> str:
        return os.path.join(self.___current_deployment_path, "{}.json".format(className))

    @property
    def __playerAddrsFilePath(self) -> str:
        return os.path.join(self.___current_deployment_path, "{}.json".format(self.COLLECTION_CONTRACTS))

    @property
    def __deploymentPath(self) -> str:
        return os.path.join(self.___current_deployment_path, self.DEPLOYMENT_FILE_NAME.format(self.___network_name, self.subFix))

    @property
    def SaveDeployConfig(self) -> str:
        return self.__deploymentPath

    @property
    def SavePlayersList(self) -> str:
        return self.__playerAddrsFilePath

    """
    :type Config the network name
    """

    def Network(self, name) -> "Paths":
        self.___network_name = name
        return self

    def SetUseHistory(self, history_path: str) -> "Paths":
        self.___current_deployment_path = os.path.join(self.___workspace, self.HISTORY_FOLDER, history_path)
        return self

    def SetUseVersion(self, version_name: str) -> "Paths":
        version = self.VERSION_NAME.format(version_name)
        self.SetUseHistory(version)
        return self

    def LoadDeploymentFile(self) -> dict:
        return json.load(codecs.open(self.__deploymentPath, 'r', 'utf-8-sig'))

    def LoadPlayerFile(self) -> dict:
        return json.load(codecs.open(self.__playerAddrsFilePath, 'r', 'utf-8-sig'))
