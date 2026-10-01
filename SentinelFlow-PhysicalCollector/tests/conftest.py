import os
import sys

_COLLECTOR_DIR = os.path.join(os.path.dirname(__file__), "..", "collector")
sys.path.insert(0, os.path.abspath(_COLLECTOR_DIR))
