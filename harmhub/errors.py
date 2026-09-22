"""通用错误：携带 HTTP 状态码与中文提示。"""


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message
