import os
import sys

# Делаем пакет sysspy импортируемым из корня проекта при запуске pytest.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
