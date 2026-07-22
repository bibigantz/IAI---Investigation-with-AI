import asyncio
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset

async def main():
    # 1. Initialize the MCP connection.
    # For a remote server using Server-Sent Events (SSE):
    mcp_server = MCPToolset("http://localhost:8000/sse")
    
    # Alternatively, for a local standard I/O server running as a subprocess:
    # mcp_server = MCPToolset("npx -y @modelcontextprotocol/server-postgres postgres://localhost/db")

    # 2. Create the agent and attach the MCP toolset
    agent = Agent(
        "google:gemini-2.5-flash",
        toolsets=[mcp_server],
        instructions="You are an intelligent data assistant. Use your available MCP tools to answer the user's questions."
    )

    # 3. Run the agent inside an async context manager
    # This ensures the connection to the MCP server is opened before the run 
    # and safely closed afterward.
    async with agent:
        print("Agent connecting to MCP server...")
        
        # The agent will automatically ask the server what tools it has,
        # decide if it needs them to answer the prompt, and execute them.
        result = await agent.run("What tools do you currently have access to, and what do they do?")
        
        print("\nAgent Response:")
        print(result.output)

if __name__ == "__main__":
    # Note: Requires a valid GOOGLE_API_KEY environment variable
    asyncio.run(main())