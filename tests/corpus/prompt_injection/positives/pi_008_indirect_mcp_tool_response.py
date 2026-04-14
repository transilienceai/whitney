"""Synthetic fixture: indirect prompt injection via MCP tool response.

The host LLM application calls an MCP server's tool. The tool's response
is concatenated into the next prompt with no separation. An attacker who
controls the MCP server (supply-chain), or an attacker whose data the MCP
server returns (e.g., a public-data MCP server), can inject instructions.

MCP is a fast-growing surface area in 2026. Every tool/resource response
from an MCP server is a potential injection vector unless the host treats
MCP outputs as untrusted data, which most current SDK examples do not.
"""
from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

client = Anthropic(api_key="REDACTED")


async def query_with_mcp(user_question: str) -> str:
    server = StdioServerParameters(command="some-mcp-server", args=[])
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_data", {"query": user_question})
            tool_output = result.content[0].text
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    f"User question: {user_question}\n\n"
                    f"Data from MCP server: {tool_output}\n\n"
                    f"Answer using the data above."
                ),
            }
        ],
    )
    return response.content[0].text
