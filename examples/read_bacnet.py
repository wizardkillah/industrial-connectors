"""Usage: python examples/read_bacnet.py 192.0.2.10 analogInput 1"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from bacnet import BacnetClient

ip, obj_type, instance = sys.argv[1], sys.argv[2], int(sys.argv[3])
with BacnetClient() as c:
    print("name :", c.read(ip, obj_type, instance, "object-name"))
    print("value:", c.read(ip, obj_type, instance), c.read(ip, obj_type, instance, "units") or "")
