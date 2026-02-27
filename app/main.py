from fastapi import FastAPI
from app.api.v1.endpoints import shield, stats
from app.core import config

app = FastAPI(
    title="PromptGuard API",
    description="AI Firewall for Generative AI Systems",
    version="1.0.0"
)

# Include routers
app.include_router(stats.router, prefix="", tags=["stats"])
app.include_router(shield.router, prefix="", tags=["shield"])

@app.on_event("startup")
async def startup_event():
    # Ensure config module is imported and env loaded
    _ = config.MONGO_URL
