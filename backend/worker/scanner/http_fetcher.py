"""The real Fetcher, built on httpx."""

import time
from types import TracebackType

import httpx

from worker.scanner.fetcher import FetchError, FetchResponse

USER_AGENT = "SentinelQA/0.1 (authorized security and QA testing)"
MAX_BODY_BYTES = 2_000_000  # enough for any normal HTML page


class HttpxFetcher:
    def __init__(
        self,
        timeout_s: float,
        *,
        max_body_bytes: int = MAX_BODY_BYTES,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._max_body_bytes = max_body_bytes
        self._client = httpx.Client(
            follow_redirects=False,  # the crawler checks every hop itself
            timeout=httpx.Timeout(timeout_s),
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            # Ignore HTTP(S)_PROXY settings so scan traffic never goes somewhere unexpected.
            trust_env=False,
            transport=transport,
        )

    def fetch(self, url: str, *, read_body: bool) -> FetchResponse:
        started = time.perf_counter()
        try:
            with self._client.stream("GET", url) as response:
                body = b""
                if read_body:
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= self._max_body_bytes:
                            break  # stop downloading huge responses
                    body = b"".join(chunks)[: self._max_body_bytes]
                return FetchResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={name.lower(): value for name, value in response.headers.items()},
                    body=body,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                )
        except httpx.TimeoutException as exc:
            raise FetchError("timeout", "Request timed out") from exc
        except httpx.InvalidURL as exc:
            raise FetchError("invalid", "Invalid URL") from exc
        except httpx.HTTPError as exc:
            raise FetchError("connection", "Connection failed") from exc

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpxFetcher":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
