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
if ! command -v abi-gen-uni &>/dev/null; then
    echo "abi-gen-uni could not be found. please check the official source from: https://www.npmjs.com/package/easy-abi-gen"
    cnpm i -g easy-abi-gen
fi

{LISTP}

"""
ITEM = """
echo "🍯 make compile of the contract from {COMPILE_COIN}"
SOLC_VERSION={SOLVER} solc --allow-paths {SOLCPATH} -o build --bin --bin-runtime --abi --optimize --metadata --overwrite {COMPILE_COIN}
echo "=> 🍺🍺🍺 {COMPILE_COIN}"

"""

ITEM_CP_LOCAL = """
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
echo "==> compile abi to python 🚸✅"
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

echo "==> compile abi to typescript 🚸✅"
"""
ITEM_TRANSPILE_GO="""
echo "==> 🚸 compile abi to golang"
local SOL=$1
local CLASSNAME=$2
local GO_CONTRACT_SRC_PATH=$3
if [[ ! -f $GO_CONTRACT_SRC_PATH/$CLASSNAME ]]; then
    mkdir -p "$GO_CONTRACT_SRC_PATH/$CLASSNAME"
fi

abigen --abi "$BUILDPATH/build/$CLASSNAME.abi" --pkg $CLASSNAME --out "$GO_CONTRACT_SRC_PATH/$CLASSNAME/init.go"

echo "==> compile abi to golang 🚸✅"
"""