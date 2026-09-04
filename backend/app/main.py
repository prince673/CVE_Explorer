"""CVE Explorer API - FastAPI Application."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .api import cve, asset, remediation, alerts, analytics


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="CVE Explorer API",
    version="2.0.0",
    description="Vulnerability intelligence platform with risk scoring, asset correlation, and remediation tracking.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cve.router)
app.include_router(asset.router)
app.include_router(remediation.router)
app.include_router(alerts.router)
app.include_router(analytics.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
