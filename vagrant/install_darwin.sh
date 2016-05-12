#!/bin/bash
# This script MOSTLY works but making it perfect is incredibly painful because
# there are some subtle differences between running in vagrant provision
# environment and interactively. You should be able to run this in an
# interactive session to build the wheel.

set -e

# M2Crypto version to build.
export VERSION="0.22.6.post2"

# Update the system
function system_update() {
  sudo softwareupdate --install --all
  sudo xcode-select -switch /Library/Developer/
}

# Install homebrew
function install_homebrew() {
  # Use /dev/null as stdin to disable prompting during install
  ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" </dev/null
  # Brew doctor complains that you are using an old version of OS X.
  brew doctor || true
  brew update
  brew install makedepend
}

function install_swig() {
  # Broken on swig 3.0.5:
  # https://github.com/M2Crypto/M2Crypto/issues/24
  brew tap homebrew/versions
  brew install homebrew/versions/swig304
}

function build_wheel() {
  sudo -H pip2.7 install --upgrade virtualenv

  virtualenv -p /usr/local/bin/python2.7 BUILD_ENV
  source BUILD_ENV/bin/activate
  pip install --upgrade pip
  pip install wheel

  cd $(mktemp -d -t build)
  # Can't use sdist in the shared folder because it wants to make hard links.
  # Can't use regular copy since it also copies the vagrant folder.
  rm -rf /m2crypto/dist
  rsync -a /m2crypto/ --exclude vagrant --exclude dist --exclude build --exclude *.whl --exclude *.egg-info .
  python setup.py sdist
  cd dist
  tar zxvf "GRR-M2Crypto-${VERSION}.tar.gz"
  cd "GRR-M2Crypto-${VERSION}"

  export OPENSSL_INSTALL_PATH="/usr/local/opt/openssl/"
  python setup.py bdist_wheel
  # VMWare shared folders are occasionally flakey so put it in the homedir too.
  cp dist/*.whl ~/
  sudo cp dist/*.whl /m2crypto/
  deactivate

  # Check that it installs
  virtualenv -p /usr/local/bin/python2.7 TEST_ENV
  source TEST_ENV/bin/activate
  pip install wheel
  pip install . 
  cd ${HOME}
  python -c "import M2Crypto"

  echo ""
  echo "Wheel built, output in current directory."
}

# We want to run unprivileged since that's what homebrew expects, but vagrant
# provisioning runs as root.
case $EUID in
  0)
    sudo -u vagrant -i $0  # script calling itself as the vagrant user
    ;;
  *)
    system_update
    install_homebrew
    brew install openssl
    brew install python
    install_swig
    build_wheel
    ;;
esac
