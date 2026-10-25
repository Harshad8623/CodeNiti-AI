"""Bounded thread-safe TTL/LRU cache; only for user opted-in requests."""
from collections import OrderedDict
from threading import Lock
import time
from config import settings

class MemoryCache:
    def __init__(self, max_items=256):
        self.data = OrderedDict()
        self.lock = Lock()
        self.max_items = max_items

    def get(self, key):
        with self.lock:
            value = self.data.get(key)
            if value is None:
                return None
            expires, result = value
            if expires <= time.monotonic():
                del self.data[key]
                return None
            self.data.move_to_end(key)
            return result

    def set(self, key, value):
        with self.lock:
            self.data[key] = (time.monotonic() + settings.cache_ttl, value)
            self.data.move_to_end(key)
            while len(self.data) > self.max_items:
                self.data.popitem(last=False)

    def clear(self):
        with self.lock:
            self.data.clear()

cache = MemoryCache()
