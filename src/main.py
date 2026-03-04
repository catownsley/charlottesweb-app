"""Main FastAPI application."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src import __version__
from src.api import router
from src.config import settings

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="HIPAA Compliance-as-Code Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware (for future frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix=settings.api_v1_prefix, tags=["api"])


@app.get("/")
def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": __version__,
        "docs": "/docs",
        "health": f"{settings.api_v1_prefix}/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
