#!/usr/bin/env bash
#
# This script builds and uploads a new release to PYPI. Make sure that the version gets updated in setup.py,
# and a release is done on GitHub at the same time.
#
# Package can be viewed online at:
# Sandbox: https://test.pypi.org/project/RsaCtfTool/
# Prod: https://pypi.org/project/RsaCtfTool/

# Installs requirements
echo Installing required tools...
pip3 install -q setuptools twine setupext-janitor

 Ask the user if production PYPI should be used, otherwise it will be the sandbox
read -p "Upload to production (y/n)?" choice
case "$choice" in
  y|Y ) PYPI_URL="https://upload.pypi.org/legacy/";;
  n|N ) PYPI_URL="https://test.pypi.org/legacy/";;
  *) exit;;
esac

# Build
echo
echo Building...
python3 setup.py sdist bdist_wheel

# Upload to PYPI
echo
echo Uploading to the following URL: $PYPI_URL
twine upload --repository-url $PYPI_URL dist/*

# Clean
echo
echo Cleaning...
python3 setup.py clean --dist --eggs