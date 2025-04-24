import bz2
import pickle
import _pickle as cPickle
import sys
import io

class SafeUnpickler(cPickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe built-in types
        safe_builtins = {
            'builtins': {'dict', 'list', 'str', 'int', 'float', 'set', 'tuple'}
        }
        if module in safe_builtins and name in safe_builtins[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Unsafe module: {module}.{name}")

def safe_load(file_obj):
    return SafeUnpickler(file_obj).load()

# Pickle a file and then compress it into a file with extension
def compress_pickle(filename, data):
    sys.stderr.write("saving pickle %s...\n" % filename)
    with bz2.BZ2File(filename, "w") as f:
        cPickle.dump(data, f)

# Load any compressed pickle file
def decompress_pickle(filename):
    sys.stderr.write("loading pickle %s...\n" % filename)
    with bz2.BZ2File(filename, 'rb') as f:
        return safe_load(f)  # from SafeUnpickler above
