from dataclasses import dataclass
from pydantic_ai import Agent, RunContext

# 1. Define what your dependencies look like
@dataclass
class DatabaseContext:
    user_id: int
    db_connection_string: str

# 2. Tell the agent what type of dependency to expect (deps_type)
bank_agent = Agent(
    "google:gemini-2.5-flash",
    deps_type=DatabaseContext,
    instructions="You are a banking assistant. Always check the user's balance before answering financial questions."
)

# 3. The tool receives the context!
@bank_agent.tool
def check_balance(ctx: RunContext[DatabaseContext]) -> float:
    """Retrieves the bank balance for the current user."""
    print(f"[System Log] Connecting to {ctx.deps.db_connection_string} for User {ctx.deps.user_id}...")
    
    # Dummy logic: User 123 has $500, everyone else has $10
    if ctx.deps.user_id == 123:
        return 500.00
    return 10.00

# 4. Pass the actual context when you run the agent
current_user_context = DatabaseContext(user_id=123, db_connection_string="postgres://localhost/bank")

result = bank_agent.run_sync(
    "Can I afford to buy a $400 watch?",
    deps=current_user_context # Injecting the dependencies here
)

print("\nAgent Response:")
print(result.output)