#!/usr/bin/env python
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
# -----------------------------------------------
{PRE_HEAD}

{LISTP}

{FOOTER}
"""
ITEM = """
echo "🍯 Compiling from {COMPILE_COIN} 🧀"
SOLC_VERSION={SOLVER} solc --evm-version {EVMVERSION} --allow-paths {SOLCPATH} -o build --bin --bin-runtime --abi --optimize-runs={RUNS} --metadata --overwrite {COMPILE_COIN}
echo "=> 🍺🍺🍺 {COMPILE_COIN}"
"""

ITEMLINK = """
echo "🍰 Compiling with LINK from {COMPILE_COIN} 🧀"
#solc --optimize --bin MetaCoin.sol | solc --link --libraries TestLib:<address>
SOLC_VERSION={SOLVER} solc --allow-paths {SOLCPATH} -o build --optimize-runs={RUNS} --bin --abi --link --libraries "{FILES_CONFIG}" --overwrite {COMPILE_COIN}
echo "=> 🍥🍥🍥 {COMPILE_COIN}"
"""

ITEM_CP_LOCAL = """
echo "==> 🚸 file system operation, move files.."
rm "{tolocation}"
cp "{fromlocation}" "{tolocation}"
"""

ITEM_TRANSPILE_PYTHON = """
if [[ ! -f {outputfolder} ]]; then
    mkdir -p {outputfolder}
fi
echo "==> 🚸 compile abi to python: {target_abi} / {outputfolder}"
abi-gen-uni --abibins {target_abi} --out "{outputfolder}" \
    --partials "{BUILDPATH}/factoryabi/PythonEthernum/partials/*.handlebars" \
    --template "{BUILDPATH}/factoryabi/PythonEthernum/contract.handlebars" \
    --language "Python"
echo "==> generate abi to python --> 🧊"
"""

ITEM_TRANSPILE_TS = """
echo "==> 🚸 compile abi to typescript"
if [[ ! -f {outputfolder} ]]; then
    mkdir -p {outputfolder}
fi

abi-gen-uni --abibins "{target_abi}" --out "{outputfolder}" \
    --partials "{BUILDPATH}/factoryabi/TypeScriptEthernum/partials/*.handlebars" \
    --template "{BUILDPATH}/factoryabi/TypeScriptEthernum/contract.handlebars" \
    --backend "web3" \
    --language "TypeScript"

echo "==> generate abi to typescript --> 🧊"
"""

ITEM_TRANSPILE_GO = """

echo "==> 🚸 compile abi to golang"
if [[ ! -f {outputfolder}/{classname} ]]; then
    mkdir -p {outputfolder}/{classname}
fi

abigen --abi {target_abi} --pkg {classname} --type {classname} --out {outputfolder}/{classname}/init.go

echo "==> generate abi to golang --> 🧊"
"""

PRE_HEAD = """

# . ./{path_definitions}

if [[ ! -d factoryabi ]]; then
  echo "The factory abi module is not found"
  exit
fi

if ! command -v abi-gen-uni &>/dev/null; then
    echo "abi-gen-uni could not be found"
    cnpm i -g easy-abi-gen
fi

if ! command -v abigen &>/dev/null; then
    echo "abigen could not be found, please go check out: https://geth.ethereum.org/downloads/"
    exit;
fi
"""
SUB_FOOTER= """

#rm localpile
#rm -rf factoryabi

"""