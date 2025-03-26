import bz2
import pickle
import _pickle as cPickle
import sys


# Pickle a file and then compress it into a file with extension
def compress_pickle(filename, data):
    sys.stderr.write("saving pickle %s...\n" % filename)
    with bz2.BZ2File(filename, "w") as f:
        cPickle.dump(data, f)


# Load any compressed pickle file
def decompress_pickle(filename):
    sys.stderr.write("loading pickle %s...\n" % filename)
    data = bz2.BZ2File(filename, "rb")
    data = cPickle.load(data)
    return data
