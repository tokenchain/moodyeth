REC = """#!/bin/bash
if [[ ! -f {TARGET_LOC} ]]; then
    mkdir -p {TARGET_LOC}/vault
fi
if [[ ! -f {TARGET_LOC}/build ]]; then
    mkdir -p {TARGET_LOC}/build
fi
#chown -R www {TARGET_LOC}/vault
cd {TARGET_LOC}
echo "🍜 changed permission to root"
SOLC_VERSION={SOLVER} solc --version


echo "and then the compiler version should be... "


{LISTP}

cd {TARGET_LOC}/build && tar -czf {COMPRESSED_NAME} *.*
mv {COMPRESSED_NAME} {TARGET_LOC}
rm -rf {TARGET_LOC}/vault
rm -rf {TARGET_LOC}/build

exit

"""


TRANS_LOCAL = """#!/bin/bash

{LISTP}



"""
ITEM = """
echo "🍯 make compile of the contract from {COMPILE_COIN}"
SOLC_VERSION={SOLVER} solc --allow-paths {SOLCPATH} -o build --bin --bin-runtime --abi --optimize --metadata --overwrite {COMPILE_COIN}
echo "=> 🍺🍺🍺 {COMPILE_COIN}"

"""

ITEM_CP_LOCAL = """
cp "{fromlocation}" "{tolocation}"
"""
