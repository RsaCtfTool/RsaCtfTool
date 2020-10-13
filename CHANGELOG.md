# Changelog

## Commit from 12/10/2020

### Fork

- Forked codebase from upstream in order to restructure project to support Poetry.

### File structure reorganization

- Attacks against single key are stored in `/src/rsactftool/attacks/single_key` folder;
- Attacks against multiple keys are stored in  `/src/rsactftool/attacks/multi_key` folder;
- Attacks are dynamically loaded;
- RsaCtfTool core is moved into `/src/rsactftool/lib` folder;
- Sage scripts are moved in `/src/rsactftool/sage` folder;
- RsaCtfTool.py is moved into `/src/rsactftool/`;
- test.sh is moved into `/test`;
- Examples are moved into `/test`.

### Updated tests in test.sh

- Refactored commands to execute testing in Poetry's Python venv.

## Ending note

Still beerware licensed :)

Test, make pull requests (and issues) and add new attacks !
Keep safe & stay at home folks !
