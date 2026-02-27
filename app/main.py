from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import shield, stats
from app.core import config
from app.repositories.log_repository import LogRepository


app = FastAPI(
    title="PromptGuard API",
    description="AI Firewall for Generative AI Systems",
    version=config.settings.APP_VERSION,
)


# Allow Streamlit UI to call the API
origins = [config.streamlit_base_url(), "http://localhost", "http://127.0.0.1"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(stats.router, prefix="/v1", tags=["stats"])
app.include_router(shield.router, prefix="/v1", tags=["shield"])


@app.on_event("startup")
async def startup_event():
    # Initialize and attach a shared LogRepository to the app state
    try:
        repo = LogRepository(mongo_uri=config.settings.MONGO_URI, db_name=config.settings.DB_NAME)
        app.state.log_repository = repo
    except Exception:
        # If DB can't be reached, app still runs but repo will be created lazily
        app.state.log_repository = None


@app.on_event("shutdown")
async def shutdown_event():
    repo = getattr(app.state, "log_repository", None)
    if repo:
        try:
            await repo.close()
        except Exception:
            pass
