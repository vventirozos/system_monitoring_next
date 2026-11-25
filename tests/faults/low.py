"""Runs the daemon with the minimum sizes lowered, for tests on tiny filesystems."""
import sys
sys.path.insert(0, "/app")
sys.dont_write_bytecode = True
import system_monitoring_next as sm
sm.MIN_FREE_FLOOR, sm.MIN_SIZE_FLOOR = 0, 1
sm.main()
