import sys

from . import mini
from . import reference

if sys.platform == "nt":
    used = reference
else:
    used = mini
