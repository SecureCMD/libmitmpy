from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ConnectionMeta:
    id: str
    dst_addr: str
    dst_port: int
    sni: Optional[str]
    alpn: List[str]
    is_tls: bool
    pid: Optional[int]
    process_name: Optional[str]
