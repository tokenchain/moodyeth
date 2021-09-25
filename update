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


swap_src(){
  local DEV_SRC=$HOME/Documents/b95/devmoody/moody
  local DEPLOY_SRC=$HOME/Documents/piplines/moodyeth/moody
  rm -rf moody
  cp -R $DEV_SRC $DEPLOY_SRC
}

pub_ver() {
  VERSION=$(cat version)
  increment_version $VERSION >version
  VERSION=$(cat version)
  
  swap_src

  sudo rm -rf dist
  rm -rf docs
  python3 -m pdoc --html moody
  mkdir -p docs
  mv html/moody docs/moody
  rm html

  python3 -m pip install --user --upgrade setuptools wheel
  # python3 -m pip install --upgrade setuptools wheel
  python3 -m readme_renderer README.rst -o ./html/README.html
  sudo python3 setup.py clean sdist bdist_wheel

  echo "========================================================="
  echo "now uploading the content to pypi"
  python3 -m twine upload dist/* --verbose

  echo "please update the package by using this command"
  echo "pip3 install moodyeth==$VERSION"
  echo "pi moodyeth==$VERSION"
  echo "pc moodyeth==$VERSION"
  echo "wait 30 seconds until it gets uploaded online..."
  # echo "ready and install it again.."
  # sudo pip3 install --proxy 127.0.0.1:1087 moodyeth==$VERSION
}

git_update() {
  git add .
  #git remote add origin https://gitee.com/jjhoc/moodyeth.git
  git commit -m "auto patched"
  #git remote add origin https://gitee.com/jjhoc/b-explorer-settings.git
  git push
}

pub_ver
git_update