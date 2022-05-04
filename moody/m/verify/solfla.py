from __future__ import print_function

import argparse as ap
import ast
import subprocess
import argparse
import os
import re
import sys

command = "solflatliner"


# solflatliner --o upgrade.sol upgradable/TransparentUpgradeableProxy.sol 0.8.12
class SolflatlinerWrapper:
    """
    This is the solidity flatliner wrapper processor
    """

    def __init__(self, root_space: str):
        self.output_file = False
        self.input_file = False
        self.proccess_result = False
        self.workspace = root_space

    def check_program(self, cmd) -> bool:
        rc = subprocess.call(['which', cmd])
        if rc == 0:
            print(f"{cmd} is installed")
            return True
        else:
            print(f"{cmd} is missing in the system")
            print(f"Try to install this via pip3 install solflatliner")
            return False

    def make_flaten_tmp_file(self, file_path_from_vault: str, version: str):
        if self.proccess_result is True:
            print(f"The subject is already success - {file_path_from_vault}")
            return

            # Split the path in head and tail pair
        head_tail = os.path.split(file_path_from_vault)
        file_name_seg = head_tail[1].split(".")

        if file_name_seg[1] != "sol":
            print("There is no sol file found in the contain")
            return

        if self.check_program(command) is False:
            return

        self.input_file = file_path_from_vault
        space_location = os.path.join(self.workspace, f"{file_name_seg[0]}_flat.sol")
        self.output_file = os.path.join("out", space_location)
        solc_args = [command]
        solc_args += ["--o"]
        solc_args += [space_location]
        solc_args += [file_path_from_vault]
        solc_args += [version]
        print(f"preprocess cmd: {solc_args}")
        solc_proc = subprocess.run(solc_args, stdout=subprocess.PIPE, universal_newlines=True)
        solc_proc.check_returncode()
        self.proccess_result = True
