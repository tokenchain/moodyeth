#!/usr/bin/env bash

# Accepts a version string and prints it incremented by one.
# Usage: increment_version <version> [<position>] [<leftmost>]
increment_version() {
  declare -a part=(${1//\./ })
  declare new
  declare -i carry=1

  for ((CNTR = ${#part[@]} - 1; CNTR >= 0; CNTR -= 1)); do
    len=${#part[CNTR]}
    new=$((part[CNTR] + carry))
    [ ${#new} -gt $len ] && carry=1 || carry=0
    [ $CNTR -gt 0 ] && part[CNTR]=${new: -len} || part[CNTR]=${new}
  done

  new="${part[*]}"
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${new// /.}"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "${new// /.}"
  elif [[ "$OSTYPE" == "cygwin" ]]; then
    echo "not correct system - cygwin detected"
    exit
  fi
}
clean_repo() {
  VERSION=$(cat version)
  increment_version $VERSION >version
  VERSION=$(cat version)

  sudo rm -rf dist
  rm -rf html
  rm -rf doc
  python3 -m pdoc --html tronpytool
  mv html/tronpytool docs/tronpytool
  rm html

  python3 -m pip install --user --upgrade setuptools wheel
  # python3 -m pip install --upgrade setuptools wheel

  sudo python3 setup.py clean sdist bdist_wheel

  # python3 -m pip install --user --upgrade twine
  # python3 -m twine upload --repository testpypi dist/*

  python3 -m twine upload dist/* --verbose

  echo "please update the package by using this command"
  echo "pip3 install tronpytool==$VERSION"
  echo "pi tronpytool==$VERSION"
  echo "pc tronpytool==$VERSION"
  echo "wait 30 seconds until it gets uploaded online..."

  # echo "ready and install it again.."
  # sudo pip3 install --proxy 127.0.0.1:1087 tronpytool==$VERSION
}
git_update() {
  git add .
  #git remote add origin https://gitee.com/jjhoc/tronpytool.git
  git commit -m "auto patched"
  #git remote add origin https://gitee.com/jjhoc/b-explorer-settings.git
  git push
}
clean_repo
git_update