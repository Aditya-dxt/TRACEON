"""
scanner/remote/stream.py

Virtual seekable binary stream backed by HTTP/1.1 Range requests.
Allows scanning multi-gigabyte models without downloading full tensor payloads.
"""

import io
import os
import urllib.request
import urllib.error
from typing import Optional, Dict


class HTTPRangeError(Exception):
    """Raised when an HTTP range request fails or range is unsupported."""
    pass


class HTTPRangeStream(io.RawIOBase):
    """
    A seekable, readable binary stream backed by HTTP Range requests.
    Features:
    - Queries Content-Length and Accept-Ranges via HEAD or 1-byte GET.
    - Caches chunks (default 64KB) to minimize round-trips for small sequential reads.
    - Tracks total `bytes_downloaded` for bandwidth savings metrics.
    """

    def __init__(
        self,
        url: str,
        chunk_size: int = 65536,
        timeout_seconds: int = 15,
        auth_token: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        opener: Optional[object] = None,
    ):
        super().__init__()
        self.url = url
        self.chunk_size = chunk_size
        self.timeout = timeout_seconds
        self.auth_token = auth_token
        self.custom_headers = custom_headers or {}
        self.opener = opener or urllib.request.urlopen
        
        self._pos = 0
        self._size: Optional[int] = None
        self._supports_range = False
        self.bytes_downloaded = 0
        
        # Simple read-ahead cache: (start_offset, bytes_buffer)
        self._cache_start = -1
        self._cache_data = b""

        self._initialize()

    def _build_request(self, headers: Optional[Dict[str, str]] = None) -> urllib.request.Request:
        req_headers = {
            "User-Agent": "Traceon-Security-Scanner/0.1.0",
            **self.custom_headers
        }
        if self.auth_token:
            req_headers["Authorization"] = f"Bearer {self.auth_token}"
        if headers:
            req_headers.update(headers)
        return urllib.request.Request(self.url, headers=req_headers)

    def _initialize(self):
        """Probes the remote URL to determine file size and HTTP Range support."""
        # 1. Try HEAD request
        head_req = self._build_request()
        head_req.get_method = lambda: "HEAD"
        try:
            with self.opener(head_req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cl = headers.get("content-length")
                if cl and cl.isdigit():
                    self._size = int(cl)
                ar = headers.get("accept-ranges", "").lower()
                if "bytes" in ar:
                    self._supports_range = True
        except (urllib.error.HTTPError, urllib.error.URLError, Exception):
            pass

        # 2. If HEAD failed or size unknown, probe with Range: bytes=0-0
        if self._size is None or not self._supports_range:
            range_req = self._build_request({"Range": "bytes=0-0"})
            try:
                with self.opener(range_req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    self.bytes_downloaded += 1
                    if resp.status == 206:
                        self._supports_range = True
                        cr = headers.get("content-range", "")
                        # e.g. "bytes 0-0/1048576"
                        if "/" in cr:
                            total_part = cr.split("/")[-1].strip()
                            if total_part.isdigit():
                                self._size = int(total_part)
                    elif resp.status == 200:
                        cl = headers.get("content-length")
                        if cl and cl.isdigit():
                            self._size = int(cl)
            except Exception as e:
                raise HTTPRangeError(f"Failed to probe remote URL {self.url}: {str(e)}") from e

        if self._size is None:
            raise HTTPRangeError(f"Could not determine Content-Length for {self.url}")

    @property
    def size(self) -> int:
        return self._size or 0

    @property
    def supports_range(self) -> bool:
        return self._supports_range

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == os.SEEK_END:
            new_pos = self.size + offset
        else:
            raise ValueError(f"Invalid whence argument: {whence}")

        if new_pos < 0:
            raise ValueError(f"Negative seek position: {new_pos}")
        self._pos = new_pos
        return self._pos

    def _fetch_range(self, start: int, length: int) -> bytes:
        """Fetches an exact byte range from the remote server."""
        if start >= self.size:
            return b""
        end = min(start + length - 1, self.size - 1)
        if start > end:
            return b""

        headers = {"Range": f"bytes={start}-{end}"}
        req = self._build_request(headers)
        try:
            with self.opener(req, timeout=self.timeout) as resp:
                data = resp.read()
                self.bytes_downloaded += len(data)
                return data
        except Exception as e:
            raise HTTPRangeError(f"HTTP Range fetch failed [{start}-{end}]: {str(e)}") from e

    def read(self, size: int = -1) -> bytes:
        if size == 0 or self._pos >= self.size:
            return b""

        if size < 0:
            # Read until EOF
            remaining = self.size - self._pos
            data = self._fetch_range(self._pos, remaining)
            self._pos += len(data)
            return data

        # Check if requested range is in cache
        cache_end = self._cache_start + len(self._cache_data)
        if self._cache_start <= self._pos < cache_end:
            offset_in_cache = self._pos - self._cache_start
            available = len(self._cache_data) - offset_in_cache
            if available >= size:
                chunk = self._cache_data[offset_in_cache : offset_in_cache + size]
                self._pos += len(chunk)
                return chunk

        # Fetch with chunk-ahead caching
        fetch_len = max(size, self.chunk_size)
        fetched = self._fetch_range(self._pos, fetch_len)
        if not fetched:
            return b""

        # Update cache
        self._cache_start = self._pos
        self._cache_data = fetched

        chunk = fetched[:size]
        self._pos += len(chunk)
        return chunk
