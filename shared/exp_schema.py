# Compatibility shim: moved in WP-0 to shared/python/exp_common/schema.py (same public API).
import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))  # noqa: I001
from exp_common.schema import *
