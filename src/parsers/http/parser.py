class HTTPParser:
    """
    Super naive HTTP response parser:
    - Waits for \r\n\r\n to end headers
    - Reads Content-Length if present
    - Otherwise treats end of connection as end of body
    """

    def parse(self, data: bytes):
        # find headers
        sep = data.find(b"\r\n\r\n")
        if sep == -1:
            return None, 0

        headers = data[:sep+4]
        body = data[sep+4:]

        content_length = None
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass
                break

        if content_length is not None:
            if len(body) < content_length:
                return None, 0
            full_msg = headers + body[:content_length]
            consumed = sep + 4 + content_length
            return full_msg, consumed

        # fallback: treat whole thing as one message
        return data, len(data)