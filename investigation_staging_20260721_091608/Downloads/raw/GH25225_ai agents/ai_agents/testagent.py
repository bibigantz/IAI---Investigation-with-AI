from pydantic_ai import Agent, RunContext

# Initialize the agent
travel_agent = Agent(
    "google:gemini-2.5-flash",
    instructions="You are a travel advisor. Use the provided tools to check weather before recommending activities."
)

# Use the @tool decorator to give the agent access to this function
@travel_agent.tool
def get_current_weather(ctx: RunContext, location: str) -> str:
    """Returns the current weather for a specific location."""
    # In a real app, you would call an external API here
    weather_db = {
        "Tokyo": "Raining heavily",
        "Paris": "Sunny and warm",
        "New York": "Snowing"
    }
    return weather_db.get(location, "Weather unknown")

# Run the agent
print("Asking about Tokyo...")
result1 = travel_agent.run_sync("What should I do today in Tokyo?")
print(result1.output)
print("-" * 30)

print("Asking about Paris...")
result2 = travel_agent.run_sync("What should I do today in Paris?")
print(result2.output)