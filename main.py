from fastapi import FastAPI, HTTPException
import uvicorn
from pydantic import ValidationError

from api.schemas import ScanRequest, AgentReport
from core.agents import run_team_pipeline

app = FastAPI()

@app.post("/scan", response_model=AgentReport)
async def scan_endpoint(req: ScanRequest):
    """
    Главный эндпоинт при запросе к которому запускается процесс мульти.ИИ.
    """
    try:
        result = await run_team_pipeline(target=req.target)
        report = AgentReport(**result)
        return report
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
