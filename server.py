"""bodybridge — MCP Server 层（最小可跑版本）"""
import os

from mcp.server.fastmcp import FastMCP

# 铁律 5/6：host/port 可配置，带合理默认值
HOST = os.environ.get("BODYBRIDGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("BODYBRIDGE_PORT", "8000"))

mcp = FastMCP(
    "bodybridge",
    host=HOST,
    port=PORT,
    stateless_http=True,  # 无状态优先：每个请求自成一体，不依赖服务端会话
)


@mcp.tool()
def ping() -> str:
    """健康检查：确认 bodybridge 桥活着。"""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
