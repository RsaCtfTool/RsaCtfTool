# this file to track the installed root directory of the tool
# so that the sage attacks can be used anywhere
import os

full_path = os.path.realpath(__file__)
root, _this_ = os.path.split(full_path)
