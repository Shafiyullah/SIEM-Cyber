import streamlit as st
import pandas as pd
import altair as alt
from elasticsearch import Elasticsearch
from config import Config

# --- Configuration & Setup ---
st.set_page_config(
    page_title="AI-Powered SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Glassmorphism & Modern UI
st.markdown("""
<style>
    .stApp {
        background: #0f172a; /* Dark blue-gray background */
        color: #e2e8f0;
    }
    .css-1d391kg {
        background-color: rgba(30, 41, 59, 0.7); /* Sidebar glass */
        backdrop-filter: blur(10px);
    }
    .metric-card {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        backdrop-filter: blur(5px);
        text-align: center;
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(45deg, #3b82f6, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-label {
        font-size: 1rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    h1, h2, h3 {
        color: #f8fafc;
    }
</style>
""", unsafe_allow_html=True)

# --- Elasticsearch Connection ---
@st.cache_resource
def get_es_client():
    try:
        scheme = "https" if Config.ES_USE_TLS else "http"
        es = Elasticsearch(
            [f"{scheme}://{Config.ES_HOST}:{Config.ES_PORT}"],
            basic_auth=(Config.ES_USER, Config.ES_PASSWORD),
            verify_certs=Config.ES_USE_TLS
        )
        if es.ping():
            return es
        else:
            st.error("Could not connect to Elasticsearch. Check your connection.")
            return None
    except Exception as e:
        st.error(f"Connection error: {e}")
        return None

es = get_es_client()

# --- Helper Functions ---
def get_recent_alerts(limit=50):
    if not es: return []
    query = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": limit
    }
    try:
        res = es.search(index=Config.ES_INDEX_NAME, body=query)
        return [hit['_source'] for hit in res['hits']['hits']]
    except Exception:
        return []

def get_stats():
    if not es: return 0, 0, 0
    try:
        # Total Logs
        total_logs = es.count(index=Config.ES_INDEX_NAME)['count']
        
        # High Severity Alerts
        high_sev_query = {"query": {"term": {"severity.keyword": "high"}}}
        high_sev = es.count(index=Config.ES_INDEX_NAME, body=high_sev_query)['count']
        
        # Critical Severity Alerts
        crit_sev_query = {"query": {"term": {"severity.keyword": "critical"}}}
        crit_sev = es.count(index=Config.ES_INDEX_NAME, body=crit_sev_query)['count']
        
        return total_logs, high_sev, crit_sev
    except Exception:
        return 0, 0, 0

# --- Dashboard Layout ---

# Header
st.title("🛡️ AI-Powered SIEM Command Center")
st.markdown("Real-time threat monitoring and AI-driven analysis.")

# Top Metrics
col1, col2, col3 = st.columns(3)
total, high, critical = get_stats()

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{total}</div>
        <div class="metric-label">Total Logs Scanned</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{high}</div>
        <div class="metric-label">High Severity Alerts</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{critical}</div>
        <div class="metric-label">Critical Threats</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Main Content Area
tab1, tab2, tab3 = st.tabs(["🚨 Live Alerts", "📊 Analytics", "🔍 Log Explorer"])

with tab1:
    st.subheader("Recent Security Alerts")
    alerts = get_recent_alerts()
    
    if alerts:
        df_alerts = pd.DataFrame(alerts)
        
        # Filter for display
        display_cols = ['timestamp', 'severity', 'source', 'message', 'ai_analysis']
        # Handle missing cols gracefully
        available_cols = [c for c in display_cols if c in df_alerts.columns]
        
        # Interactive Table
        st.dataframe(
            df_alerts[available_cols],
            use_container_width=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", format="D MMM, HH:mm:ss"),
                "severity": st.column_config.TextColumn("Severity"),
                "ai_analysis": st.column_config.Column("AI Insight", width="large")
            }
        )
        
        # Detail View
        selected_row = st.selectbox("Select an alert to view AI Analysis details:", df_alerts.index)
        if selected_row is not None:
            row = df_alerts.loc[selected_row]
            with st.expander("🤖 AI Analysis & Recommendations", expanded=True):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown(f"**Summary:** {row.get('ai_analysis', {}).get('summary', 'N/A')}")
                    st.markdown(f"**Severity:** {row.get('severity', 'N/A')}")
                with col_b:
                    st.markdown(f"**Recommendation:** {row.get('ai_analysis', {}).get('recommendation', 'N/A')}")
                    st.json(row.get('ai_analysis', {}))
    else:
        st.info("No alerts found yet. System is monitoring...")

with tab2:
    st.subheader("Threat Analytics")
    if alerts:
        df = pd.DataFrame(alerts)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Time Series Chart
            chart = alt.Chart(df).mark_line(point=True).encode(
                x='timestamp',
                y='count()',
                color='severity',
                tooltip=['timestamp', 'severity', 'count()']
            ).properties(title="Alerts Over Time").interactive()
            
            st.altair_chart(chart, use_container_width=True)
            
            # Severity Distribution
            chart_pie = alt.Chart(df).mark_arc(innerRadius=50).encode(
                theta='count()',
                color='severity',
                tooltip=['severity', 'count()']
            ).properties(title="Severity Distribution")
            
            st.altair_chart(chart_pie, use_container_width=True)

with tab3:
    st.subheader("Raw Log Explorer")
    search_term = st.text_input("Search logs...", placeholder="Enter IP, keyword, or error code")
    
    if st.button("Search"):
        if es:
            query = {
                "query": {
                    "multi_match": {
                        "query": search_term,
                        "fields": ["message", "raw_log", "source", "ip"]
                    }
                },
                "size": 20
            }
            res = es.search(index=Config.ES_INDEX_NAME, body=query)
            hits = [hit['_source'] for hit in res['hits']['hits']]
            st.dataframe(hits)
