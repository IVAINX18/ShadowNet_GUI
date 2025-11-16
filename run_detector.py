#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gui'))

from gui.main_window import main

if __name__ == "__main__":
    main()
