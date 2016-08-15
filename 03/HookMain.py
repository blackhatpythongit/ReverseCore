from ctypes import *

windll.KeyHook.HookStart()
raw_input("input 'q' to stop: ")
windll.KeyHook.HookStop()
