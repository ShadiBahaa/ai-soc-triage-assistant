"""
Streamlit UI for AI SOC Analyst.
Provides an interactive web interface for the triage pipeline.
"""

import sys
from pathlib import Path
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

# Page configuration
st.set_page_config(
    page_title="AI SOC Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .severity-critical { background-color: #dc3545; color: white; padding: 5px 10px; border-radius: 5px; }
    .severity-high { background-color: #fd7e14; color: white; padding: 5px 10px; border-radius: 5px; }
    .severity-medium { background-color: #ffc107; color: black; padding: 5px 10px; border-radius: 5px; }
    .severity-low { background-color: #28a745; color: white; padding: 5px 10px; border-radius: 5px; }
    .incident-card {
        border: 1px solid #ddd;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
        background-color: #f8f9fa;
    }
    .metric-container {
        text-align: center;
        padding: 20px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        color: white;
        margin: 5px;
    }
</style>
""", unsafe_allow_html=True)


def load_incidents():
    """Load incidents from processed file."""
    incidents_path = Path("data/processed/incidents.jsonl")
    if not incidents_path.exists():
        return []
    
    incidents = []
    with incidents_path.open("r") as f:
        for line in f:
            if line.strip():
                incidents.append(json.loads(line))
    return incidents


def load_events():
    """Load normalized events."""
    events_path = Path("data/processed/normalized_events.jsonl")
    if not events_path.exists():
        return []
    
    events = []
    with events_path.open("r") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    return events


def severity_badge(severity: str) -> str:
    """Generate HTML badge for severity."""
    colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745"
    }
    color = colors.get(severity.lower(), "#6c757d")
    text_color = "black" if severity.lower() == "medium" else "white"
    return f'<span style="background-color: {color}; color: {text_color}; padding: 3px 10px; border-radius: 5px; font-weight: bold;">{severity.upper()}</span>'


def main():
    """Main Streamlit application."""
    
    # Sidebar
    st.sidebar.title("🛡️ AI SOC Analyst")
    st.sidebar.markdown("---")
    
    page = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Run Pipeline", "Incidents", "Events", "Settings"]
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Quick Stats")
    
    events = load_events()
    incidents = load_incidents()
    
    st.sidebar.metric("Total Events", len(events))
    st.sidebar.metric("Incidents", len(incidents))
    
    # Main content
    if page == "Dashboard":
        show_dashboard(events, incidents)
    elif page == "Run Pipeline":
        show_pipeline()
    elif page == "Incidents":
        show_incidents(incidents)
    elif page == "Events":
        show_events(events)
    elif page == "Settings":
        show_settings()


def show_dashboard(events, incidents):
    """Display main dashboard."""
    st.title("🛡️ AI SOC Analyst Dashboard")
    st.markdown("*AI-assisted Security Operations Center for Log Summarization and Incident Triage*")
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📊 Total Events", f"{len(events):,}")
    
    with col2:
        st.metric("🚨 Incidents", len(incidents))
    
    # Calculate severity distribution
    from src.triage.score import score_incident
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        triage = score_incident(inc.get("signals", []))
        sev = triage["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    with col3:
        critical_high = severity_counts["critical"] + severity_counts["high"]
        st.metric("⚠️ Critical/High", critical_high)
    
    with col4:
        from src.llm.client import llm_enabled
        llm_status = "✅ Enabled" if llm_enabled() else "❌ Disabled"
        st.metric("🤖 LLM Status", llm_status)
    
    st.markdown("---")
    
    # Severity distribution chart
    if incidents:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Severity Distribution")
            import pandas as pd
            severity_df = pd.DataFrame([
                {"Severity": "Critical", "Count": severity_counts["critical"]},
                {"Severity": "High", "Count": severity_counts["high"]},
                {"Severity": "Medium", "Count": severity_counts["medium"]},
                {"Severity": "Low", "Count": severity_counts["low"]}
            ])
            st.bar_chart(severity_df.set_index("Severity"))
        
        with col2:
            st.subheader("📊 Event Sources")
            source_counts = {}
            for evt in events:
                src = evt.get("source", "unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
            
            source_df = pd.DataFrame([
                {"Source": k, "Count": v} for k, v in source_counts.items()
            ])
            if not source_df.empty:
                st.bar_chart(source_df.set_index("Source"))
        
        # Recent incidents
        st.markdown("---")
        st.subheader("🚨 Recent Incidents")
        
        for inc in incidents[:5]:
            triage = score_incident(inc.get("signals", []))
            severity = triage["severity"]
            
            with st.expander(f"{inc.get('incident_id')} - {inc.get('incident_type')} [{severity.upper()}]"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Host:** `{inc.get('key', {}).get('host', 'Unknown')}`")
                    st.markdown(f"**User:** `{inc.get('key', {}).get('user', 'Unknown')}`")
                    st.markdown(f"**Source IP:** `{inc.get('key', {}).get('src_ip', 'Unknown')}`")
                with col2:
                    st.markdown(f"**Severity:** {severity.upper()}")
                    st.markdown(f"**Confidence:** {triage['confidence']*100:.0f}%")
                    st.markdown(f"**Events:** {inc.get('event_count', 0)}")
                
                st.markdown("**Signals:**")
                for sig in inc.get("signals", []):
                    st.markdown(f"- {sig.get('signal')}: {sig.get('description', '')}")
    else:
        st.info("No incidents found. Run the pipeline to analyze security logs.")


def show_pipeline():
    """Display pipeline controls."""
    st.title("🔄 Run Pipeline")
    st.markdown("Execute the security log analysis pipeline.")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Pipeline Options")
        generate_logs = st.checkbox("Generate new sample logs", value=False)
        write_cases = st.checkbox("Write case files", value=True)
        use_llm = st.checkbox("Use LLM for summarization", value=False)
    
    with col2:
        st.subheader("Pipeline Steps")
        st.markdown("""
        1. **Generate Logs** - Create synthetic security events
        2. **Normalize** - Convert to common schema
        3. **Correlate** - Group events into incidents
        4. **Triage** - Score severity and generate summaries
        5. **Export** - Write case files (JSON + Markdown)
        """)
    
    st.markdown("---")
    
    if st.button("🚀 Run Full Pipeline", type="primary"):
        with st.spinner("Running pipeline..."):
            try:
                from src.api.pipeline import run_full_pipeline
                result = run_full_pipeline(
                    generate_logs=generate_logs,
                    write_cases=write_cases,
                    use_llm=use_llm
                )
                
                if result["success"]:
                    st.success(f"✅ Pipeline completed! Processed {result['incident_count']} incidents.")
                    
                    # Show results
                    for res in result.get("results", []):
                        with st.expander(f"{res['incident_id']} - {res['incident_type']}"):
                            st.json(res["triage"])
                            st.markdown("### Summary")
                            st.markdown(res["summary"])
                else:
                    st.error(f"❌ Pipeline failed: {result.get('error', 'Unknown error')}")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    st.markdown("---")
    st.subheader("Individual Steps")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📝 Generate Logs"):
            with st.spinner("Generating..."):
                try:
                    from src.data.generate_sample_logs import main as gen_main
                    gen_main()
                    st.success("✅ Logs generated!")
                except Exception as e:
                    st.error(f"Error: {e}")
    
    with col2:
        if st.button("🔄 Normalize"):
            with st.spinner("Normalizing..."):
                try:
                    from src.parsing.normalize import main as norm_main
                    norm_main()
                    st.success("✅ Events normalized!")
                except Exception as e:
                    st.error(f"Error: {e}")
    
    with col3:
        if st.button("🔗 Correlate"):
            with st.spinner("Correlating..."):
                try:
                    from src.correlation.correlate import main as corr_main
                    corr_main()
                    st.success("✅ Events correlated!")
                except Exception as e:
                    st.error(f"Error: {e}")


def show_incidents(incidents):
    """Display incidents list and details."""
    st.title("🚨 Incidents")
    
    if not incidents:
        st.info("No incidents found. Run the pipeline first.")
        return
    
    # Filter controls
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"]
        )
    with col2:
        search = st.text_input("Search incidents")
    
    st.markdown("---")
    
    from src.triage.score import score_incident
    from src.triage.summarize import summarize_incident
    
    for inc in incidents:
        triage = score_incident(inc.get("signals", []))
        
        if triage["severity"] not in severity_filter:
            continue
        
        if search and search.lower() not in json.dumps(inc).lower():
            continue
        
        severity = triage["severity"]
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        
        with st.expander(f"{emoji} {inc.get('incident_id')} - {inc.get('incident_type')}"):
            tabs = st.tabs(["Overview", "Summary", "MITRE", "Actions", "Raw Data"])
            
            with tabs[0]:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Incident ID:** `{inc.get('incident_id')}`")
                    st.markdown(f"**Type:** {inc.get('incident_type')}")
                    st.markdown(f"**Severity:** {severity.upper()}")
                    st.markdown(f"**Confidence:** {triage['confidence']*100:.0f}%")
                with col2:
                    st.markdown(f"**Host:** `{inc.get('key', {}).get('host')}`")
                    st.markdown(f"**User:** `{inc.get('key', {}).get('user')}`")
                    st.markdown(f"**Source IP:** `{inc.get('key', {}).get('src_ip')}`")
                    st.markdown(f"**Events:** {inc.get('event_count')}")
                
                st.markdown("**Signals:**")
                for sig in inc.get("signals", []):
                    st.markdown(f"- **{sig.get('signal')}**: {sig.get('description', 'N/A')}")
            
            with tabs[1]:
                summary = summarize_incident(inc, triage)
                st.markdown(summary)
            
            with tabs[2]:
                st.markdown("### MITRE ATT&CK Mapping")
                for m in triage.get("mitre", []):
                    st.markdown(f"**[{m['technique']}]({m.get('url', '#')})** - {m['technique_name']}")
                    st.markdown(f"- Tactic: {m['tactic']}")
                    st.markdown(f"- {m.get('description', '')}")
                    st.markdown("---")
            
            with tabs[3]:
                st.markdown("### Recommended Actions")
                for i, action in enumerate(triage.get("recommended_actions", []), 1):
                    st.markdown(f"{i}. {action}")
            
            with tabs[4]:
                st.json(inc)


def show_events(events):
    """Display events list."""
    st.title("📊 Events")
    
    if not events:
        st.info("No events found. Run the pipeline first.")
        return
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        source_filter = st.multiselect(
            "Filter by Source",
            list(set(e.get("source") for e in events)),
            default=list(set(e.get("source") for e in events))
        )
    with col2:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["high", "medium", "low", "none"],
            default=["high", "medium", "low", "none"]
        )
    with col3:
        limit = st.number_input("Max events to show", 10, 1000, 100)
    
    st.markdown("---")
    
    # Filter events
    filtered = []
    for evt in events:
        if evt.get("source") not in source_filter:
            continue
        sev = evt.get("severity_hint") or "none"
        if sev not in severity_filter:
            continue
        filtered.append(evt)
    
    st.markdown(f"Showing {min(len(filtered), limit)} of {len(filtered)} events")
    
    # Display as table
    import pandas as pd
    df_data = []
    for evt in filtered[:limit]:
        df_data.append({
            "Timestamp": evt.get("timestamp", "")[:19],
            "Source": evt.get("source", ""),
            "Host": evt.get("host", ""),
            "User": evt.get("user", ""),
            "Event Type": evt.get("event_type", ""),
            "Severity": evt.get("severity_hint") or "none"
        })
    
    if df_data:
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True)


def show_settings():
    """Display settings page."""
    st.title("⚙️ Settings")
    
    st.subheader("LLM Configuration")
    
    from src.llm.client import llm_enabled, get_provider
    
    st.markdown(f"**Current Status:** {'✅ Enabled' if llm_enabled() else '❌ Disabled'}")
    st.markdown(f"**Provider:** {get_provider()}")
    
    st.info("""
    To enable LLM summarization:
    1. Copy `.env.example` to `.env`
    2. Set `LLM_PROVIDER` to `openai`, `anthropic`, or `local`
    3. Set `LLM_API_KEY` with your API key
    4. Optionally set `LLM_MODEL` for a specific model
    """)
    
    st.markdown("---")
    st.subheader("Data Paths")
    
    st.code("""
    Raw Logs:        data/raw/sample_logs.jsonl
    Normalized:      data/processed/normalized_events.jsonl
    Incidents:       data/processed/incidents.jsonl
    Case Files:      docs/cases/
    """)
    
    st.markdown("---")
    st.subheader("About")
    
    st.markdown("""
    **AI SOC Triage Assistant** v1.0.0
    
    An AI-assisted Security Operations Center workflow for:
    - Log ingestion and normalization
    - Event correlation into incidents
    - Severity scoring with MITRE ATT&CK mapping
    - Automated summarization
    - Case file export
    
    This is a defensive security tool for analysis, triage, and reporting.
    """)


if __name__ == "__main__":
    main()
