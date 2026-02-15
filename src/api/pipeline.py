"""
Pipeline orchestration module for AI SOC Analyst.
Coordinates the full analysis pipeline from raw logs to case files.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.triage.score import score_incident
from src.triage.summarize import summarize_incident
from src.utils.case_writer import write_case, write_executive_summary
from src.llm.client import llm_enabled
from src.llm.prompts import incident_prompt

INCIDENTS_PATH = Path("data/processed/incidents.jsonl")
NORMALIZED_PATH = Path("data/processed/normalized_events.jsonl")


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Read JSON Lines file into list."""
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def run_pipeline(
    write_cases: bool = True,
    use_llm: bool = False,
    incidents_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Run the full triage pipeline on correlated incidents.
    
    Args:
        write_cases: Whether to write case files (JSON + Markdown)
        use_llm: Whether to use LLM for summarization (if available)
        incidents_path: Optional custom path to incidents file
        
    Returns:
        List of processed incidents with triage and summaries
    """
    inc_path = incidents_path or INCIDENTS_PATH
    incidents = read_jsonl(inc_path)
    
    if not incidents:
        print("No incidents found. Run the correlation step first.")
        return []
    
    results = []
    
    for incident in incidents:
        # Score the incident
        triage = score_incident(incident.get("signals", []))
        
        # Generate summary
        if use_llm and llm_enabled():
            try:
                from src.llm.client import generate_summary
                prompt = incident_prompt(incident, triage)
                summary = generate_summary(prompt)
            except Exception as e:
                print(f"LLM summarization failed, using deterministic: {e}")
                summary = summarize_incident(incident, triage)
        else:
            summary = summarize_incident(incident, triage)
        
        # Write case files
        if write_cases:
            write_case(incident, triage, summary)
        
        # Compile result
        result = {
            "incident_id": incident.get("incident_id"),
            "incident_type": incident.get("incident_type"),
            "key": incident.get("key"),
            "time_range": incident.get("time_range"),
            "signals": incident.get("signals"),
            "event_count": incident.get("event_count"),
            "triage": triage,
            "summary": summary
        }
        results.append(result)
    
    # Write executive summary if cases were written
    if write_cases and results:
        # Count total events from normalized file
        normalized_events = read_jsonl(NORMALIZED_PATH)
        total_events = len(normalized_events)
        write_executive_summary(results, total_events)
    
    return results


def run_full_pipeline(
    generate_logs: bool = False,
    write_cases: bool = True,
    use_llm: bool = False
) -> Dict[str, Any]:
    """
    Run the complete pipeline from log generation to case export.
    
    Args:
        generate_logs: Whether to generate new sample logs
        write_cases: Whether to write case files
        use_llm: Whether to use LLM for summarization
        
    Returns:
        Pipeline execution summary
    """
    from src.data.generate_sample_logs import main as generate_main
    from src.parsing.normalize import main as normalize_main
    from src.correlation.correlate import main as correlate_main
    
    steps_completed = []
    
    try:
        # Step 1: Generate sample logs (optional)
        if generate_logs:
            print("\n=== Step 1: Generating sample logs ===")
            generate_main()
            steps_completed.append("generate_logs")
        
        # Step 2: Normalize logs
        print("\n=== Step 2: Normalizing logs ===")
        normalize_main()
        steps_completed.append("normalize")
        
        # Step 3: Correlate events into incidents
        print("\n=== Step 3: Correlating events ===")
        correlate_main()
        steps_completed.append("correlate")
        
        # Step 4: Triage and summarize
        print("\n=== Step 4: Triaging and summarizing incidents ===")
        results = run_pipeline(write_cases=write_cases, use_llm=use_llm)
        steps_completed.append("triage")
        
        print(f"\n=== Pipeline complete ===")
        print(f"Processed {len(results)} incidents")
        
        return {
            "success": True,
            "steps_completed": steps_completed,
            "incident_count": len(results),
            "results": results
        }
        
    except Exception as e:
        return {
            "success": False,
            "steps_completed": steps_completed,
            "error": str(e)
        }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AI SOC Triage Pipeline")
    parser.add_argument("--generate", action="store_true", help="Generate new sample logs")
    parser.add_argument("--no-cases", action="store_true", help="Skip writing case files")
    parser.add_argument("--llm", action="store_true", help="Use LLM for summarization")
    
    args = parser.parse_args()
    
    result = run_full_pipeline(
        generate_logs=args.generate,
        write_cases=not args.no_cases,
        use_llm=args.llm
    )
    
    if result["success"]:
        print(f"\n✅ Pipeline completed successfully!")
        print(f"   Incidents: {result['incident_count']}")
        print(f"   Cases written to: docs/cases/")
    else:
        print(f"\n❌ Pipeline failed: {result.get('error', 'Unknown error')}")
