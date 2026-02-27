from fastapi import APIRouter, Depends, Request, HTTPException
from app.repositories.log_repository import LogRepository, get_default_repo

router = APIRouter()


async def get_repo(request: Request) -> LogRepository:
    repo = getattr(request.app.state, "log_repository", None)
    if repo is None:
        repo = get_default_repo()
    return repo


@router.get("/summary")
async def summary(repo: LogRepository = Depends(get_repo)):
    try:
        return await repo.get_analytics_summary()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs")
async def logs(limit: int = 100, repo: LogRepository = Depends(get_repo)):
    try:
        return await repo.get_recent_logs(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
