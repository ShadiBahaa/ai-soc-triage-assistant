"""
FastAPI application for AI SOC Analyst.
Provides REST API endpoints for the triage pipeline.
"""

import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.api.pipeline import run_pipeline, run_full_pipeline, read_jsonl
from src.llm.client import llm_enabled


# Pydantic models for API responses
class TriageResult(BaseModel):
    severity: str
    severity_score: float
    confidence: float
    mitre: List[dict]
    recommended_actions: List[str]
    requires_immediate_attention: bool


class IncidentResult(BaseModel):
    incident_id: str
    incident_type: str
    key: dict
    time_range: dict
    signals: List[dict]
    event_count: int
    triage: dict
    summary: str


class PipelineResponse(BaseModel):
    success: bool
    timestamp: str
    count: int
    results: List[dict]
    llm_enabled: bool


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    llm_available: bool
    version: str


# Create FastAPI app
app = FastAPI(
    title="AI SOC Triage Assistant",
    description="AI-assisted SOC workflow for log summarization and incident triage",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


@app.get("/", tags=["Health"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "AI SOC Triage Assistant",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "run_pipeline": "/run",
            "run_full": "/run/full",
            "incidents": "/incidents",
            "docs": "/docs"
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "llm_available": llm_enabled(),
        "version": "1.0.0"
    }


@app.get("/run", response_model=PipelineResponse, tags=["Pipeline"])
def run_triage_pipeline(
    write_cases: bool = Query(True, description="Write case files to disk"),
    use_llm: bool = Query(False, description="Use LLM for summarization")
):
    """
    Run the triage pipeline on existing correlated incidents.
    
    This endpoint processes incidents that have already been correlated
    and generates triage scores, summaries, and case files.
    """
    try:
        results = run_pipeline(write_cases=write_cases, use_llm=use_llm)
        
        return {
            "success": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "count": len(results),
            "results": results,
            "llm_enabled": llm_enabled()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/run/full", tags=["Pipeline"])
def run_full_triage_pipeline(
    generate_logs: bool = Query(False, description="Generate new sample logs"),
    write_cases: bool = Query(True, description="Write case files to disk"),
    use_llm: bool = Query(False, description="Use LLM for summarization")
):
    """
    Run the complete pipeline from log generation to case export.
    
    This endpoint runs all pipeline steps:
    1. Generate sample logs (optional)
    2. Normalize logs
    3. Correlate events into incidents
    4. Triage and summarize
    5. Write case files
    """
    try:
        result = run_full_pipeline(
            generate_logs=generate_logs,
            write_cases=write_cases,
            use_llm=use_llm
        )
        
        result["timestamp"] = datetime.utcnow().isoformat() + "Z"
        result["llm_enabled"] = llm_enabled()
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents", tags=["Data"])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)")
):
    """
    List all correlated incidents.
    
    Returns the list of incidents from the processed data without
    running the full pipeline.
    """
    try:
        incidents_path = Path("data/processed/incidents.jsonl")
        incidents = read_jsonl(incidents_path)
        
        # Apply severity filter if provided (requires triage data)
        if severity:
            # Re-score each incident to get severity
            from src.triage.score import score_incident
            filtered = []
            for inc in incidents:
                triage = score_incident(inc.get("signals", []))
                if triage["severity"] == severity.lower():
                    inc["triage"] = triage
                    filtered.append(inc)
            incidents = filtered
        
        return {
            "count": len(incidents),
            "incidents": incidents
        }
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, 
            detail="No incidents found. Run the correlation step first."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}", tags=["Data"])
def get_incident(incident_id: str):
    """
    Get a specific incident by ID.
    
    Returns the incident details along with triage and summary.
    """
    try:
        incidents_path = Path("data/processed/incidents.jsonl")
        incidents = read_jsonl(incidents_path)
        
        for inc in incidents:
            if inc.get("incident_id") == incident_id:
                # Add triage and summary
                from src.triage.score import score_incident
                from src.triage.summarize import summarize_incident
                
                triage = score_incident(inc.get("signals", []))
                summary = summarize_incident(inc, triage)
                
                return {
                    "incident": inc,
                    "triage": triage,
                    "summary": summary
                }
        
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", tags=["Data"])
def get_statistics():
    """
    Get pipeline statistics and summary.
    
    Returns counts and distribution of events and incidents.
    """
    try:
        normalized_path = Path("data/processed/normalized_events.jsonl")
        incidents_path = Path("data/processed/incidents.jsonl")
        
        events = read_jsonl(normalized_path)
        incidents = read_jsonl(incidents_path)
        
        # Calculate statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = {}
        
        from src.triage.score import score_incident
        
        for inc in incidents:
            triage = score_incident(inc.get("signals", []))
            sev = triage["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            inc_type = inc.get("incident_type", "Unknown")
            type_counts[inc_type] = type_counts.get(inc_type, 0) + 1
        
        # Event source distribution
        source_counts = {}
        for evt in events:
            src = evt.get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
        
        return {
            "events": {
                "total": len(events),
                "by_source": source_counts
            },
            "incidents": {
                "total": len(incidents),
                "by_severity": severity_counts,
                "by_type": type_counts
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Run with: uvicorn src.api.app:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
