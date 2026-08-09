"""NetProbe Streamlit Web Application."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from banner_grabber import grab_banner
from os_fingerprint import fingerprint_os
from output import build_payload
from scanner import scan_ports
from utils import DEFAULT_COMMON_PORTS, NetProbeError, parse_ports, resolve_target

# Page Configuration
st.set_page_config(
    page_title="NetProbe - Network Reconnaissance Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Dark Cyber Security Theme)
st.markdown(
    """
    <style>
    /* Dark Theme Customization */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Header Styling */
    .netprobe-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 242, 254, 0.08);
    }
    
    .netprobe-title {
        font-family: 'Inter', system-ui, sans-serif;
        font-weight: 800;
        background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.5rem;
        margin: 0;
        letter-spacing: -0.5px;
    }
    
    .netprobe-subtitle {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-top: 6px;
    }
    
    /* Card Component */
    .metric-card {
        background: #151d30;
        border: 1px solid #23314f;
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
        transition: transform 0.2s, border-color 0.2s;
    }
    .metric-card:hover {
        border-color: #00f2fe;
        transform: translateY(-2px);
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #64748b;
    }

    /* Status Colors */
    .val-open { color: #10b981; }
    .val-filtered { color: #f59e0b; }
    .val-closed { color: #ef4444; }
    .val-scanned { color: #3b82f6; }
    .val-time { color: #a855f7; }

    /* OS Badge */
    .os-panel {
        background: rgba(30, 41, 59, 0.7);
        border-left: 4px solid #00f2fe;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 20px;
    }
    
    .badge-high { background-color: #065f46; color: #34d399; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    .badge-medium { background-color: #92400e; color: #fbbf24; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    .badge-low { background-color: #991b1b; color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header Section
st.markdown(
    """
    <div class="netprobe-header">
        <div style="display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 2.8rem;">🛡️</span>
            <div>
                <h1 class="netprobe-title">NETPROBE</h1>
                <div class="netprobe-subtitle">Network Reconnaissance, Concurrent Port Scanner & OS Fingerprinting</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Target & Configuration")
    
    target_input = st.text_input(
        "Target Address / Hostname",
        value="127.0.0.1",
        help="Enter an IP address (e.g. 192.168.1.1) or hostname (e.g. scanme.nmap.org)",
    )
    
    st.subheader("🎯 Port Selection")
    port_mode = st.radio(
        "Port Mode",
        options=["Presets", "Custom List / Range"],
        index=0,
    )
    
    if port_mode == "Presets":
        preset_choice = st.selectbox(
            "Select Preset",
            options=[
                "Default Common Ports (32 ports)",
                "Web Services (80, 443, 8000, 8080, 8443)",
                "Database Ports (1433, 1521, 3306, 5432, 6379, 27017)",
                "Top 100 Ports (1-100)",
                "All Well-Known Ports (1-1024)",
            ],
        )
        if "Default" in preset_choice:
            port_spec = None
        elif "Web" in preset_choice:
            port_spec = "80,443,8000,8080,8443"
        elif "Database" in preset_choice:
            port_spec = "1433,1521,3306,5432,6379,27017"
        elif "Top 100" in preset_choice:
            port_spec = "1-100"
        else:
            port_spec = "1-1024"
    else:
        port_spec = st.text_input(
            "Custom Ports (comma-separated / ranges)",
            value="22, 80, 443, 8000-8080",
            help="Example: 22, 80, 443 or 1-1024",
        )
        
    st.subheader("⚡ Scan Settings")
    grab_banners = st.checkbox("Enable Banner Grabbing", value=True)
    detect_os = st.checkbox("Enable OS Fingerprinting", value=True)
    show_closed = st.checkbox("Show Closed & Filtered Ports in Table", value=False)
    
    st.subheader("🛠️ Performance")
    timeout = st.slider("Connection Timeout (seconds)", min_value=0.1, max_value=5.0, value=1.0, step=0.1)
    threads = st.slider("Worker Threads", min_value=1, max_value=200, value=100, step=10)
    
    scan_button = st.button("🚀 Launch NetProbe Scan", type="primary", use_container_width=True)

# Initialize Session State for results persistence
if "scan_data" not in st.session_state:
    st.session_state.scan_data = None

# Scan Trigger Execution
if scan_button:
    if not target_input.strip():
        st.error("Please enter a valid target IP address or hostname.")
    else:
        try:
            with st.spinner(f"Resolving {target_input}..."):
                target_ip = resolve_target(target_input.strip())
                requested_ports = parse_ports(port_spec)
                
            progress_bar = st.progress(0, text=f"Scanning {len(requested_ports)} ports on {target_ip}...")
            
            started_at = time.perf_counter()
            
            # Execute scanner
            results = scan_ports(
                target=target_ip,
                ports=requested_ports,
                timeout=timeout,
                max_workers=threads,
                grab_banners=grab_banners,
            )
            elapsed = time.perf_counter() - started_at
            
            progress_bar.progress(80, text="Performing OS fingerprinting..." if detect_os else "Finalizing results...")
            
            os_info = None
            if detect_os:
                open_ports = [result.port for result in results if result.status == "open"]
                os_info = fingerprint_os(target_ip, open_ports=open_ports, timeout=timeout)
                
            progress_bar.progress(100, text="Scan complete!")
            time.sleep(0.3)
            progress_bar.empty()
            
            # Store in session state
            st.session_state.scan_data = {
                "target": target_input.strip(),
                "target_ip": target_ip,
                "requested_ports": requested_ports,
                "results": results,
                "elapsed": elapsed,
                "os_info": os_info,
                "grab_banners": grab_banners,
            }
            st.toast("Scan completed successfully!", icon="✅")
        except NetProbeError as err:
            st.error(f"NetProbe Error: {err}")
        except Exception as err:
            st.error(f"An unexpected error occurred: {err}")

# Render Scan Dashboard if scan_data is present
if st.session_state.scan_data:
    data = st.session_state.scan_data
    results = data["results"]
    os_info = data["os_info"]
    elapsed = data["elapsed"]
    target_ip = data["target_ip"]
    target_name = data["target"]
    
    open_count = sum(1 for r in results if r.status == "open")
    filtered_count = sum(1 for r in results if r.status == "filtered")
    closed_count = sum(1 for r in results if r.status == "closed")
    total_count = len(results)
    
    # Target Info Banner
    st.info(f"📍 **Target**: `{target_name}` ({target_ip}) | **Ports Scanned**: `{total_count}` | **Scan Time**: `{elapsed:.2f}s`")
    
    # Summary Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Scanned</div>
                <div class="metric-value val-scanned">{total_count}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Open Ports</div>
                <div class="metric-value val-open">{open_count}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Filtered</div>
                <div class="metric-value val-filtered">{filtered_count}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m4:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Closed</div>
                <div class="metric-value val-closed">{closed_count}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m5:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Duration</div>
                <div class="metric-value val-time">{elapsed:.2f}s</div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # OS Fingerprint Section
    if os_info:
        st.subheader("🖥️ OS Fingerprint Analysis")
        conf_class = f"badge-{os_info.confidence}"
        ttl_str = f" (Observed Ping TTL: {os_info.ttl})" if os_info.ttl is not None else ""
        
        st.markdown(
            f"""
            <div class="os-panel">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <span style="font-size: 1.2rem; font-weight: 700; color: #f8fafc;">Probable OS: {os_info.probable_os}</span>
                        <span class="{conf_class}" style="margin-left: 10px;">{os_info.confidence.upper()} CONFIDENCE</span>
                        <span style="color: #94a3b8; font-size: 0.9rem;">{ttl_str}</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander("🔍 View Fingerprint Heuristic Signals"):
            for sig in os_info.signals:
                st.markdown(f"- {sig}")

    # Visual Analytics Row
    st.subheader("📊 Visual Scan Analytics")
    c1, c2 = st.columns(2)
    
    with c1:
        # Donut Chart for Port Status
        status_counts = {"Open": open_count, "Filtered": filtered_count, "Closed": closed_count}
        df_status = pd.DataFrame(list(status_counts.items()), columns=["Status", "Count"])
        df_status = df_status[df_status["Count"] > 0]
        
        fig_donut = px.pie(
            df_status,
            values="Count",
            names="Status",
            hole=0.55,
            color="Status",
            color_discrete_map={
                "Open": "#10b981",
                "Filtered": "#f59e0b",
                "Closed": "#ef4444",
            },
            title="Port Status Breakdown",
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            margin=dict(t=40, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_donut, use_container_width=True)
        
    with c2:
        # Latency Bar Chart for Open/Scanned Ports
        visible_items = [r for r in results if r.status == "open"] if not show_closed else results
        if visible_items:
            df_lat = pd.DataFrame([
                {
                    "Port": f"{r.port} ({r.service})",
                    "Latency (ms)": r.latency_ms if r.latency_ms is not None else 0,
                    "Status": r.status,
                }
                for r in visible_items
            ])
            
            fig_bar = px.bar(
                df_lat,
                x="Port",
                y="Latency (ms)",
                color="Status",
                color_discrete_map={
                    "open": "#10b981",
                    "filtered": "#f59e0b",
                    "closed": "#ef4444",
                },
                title="Response Latency per Port (ms)",
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                margin=dict(t=40, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No open ports found to plot latency.")

    # Results Table Section
    st.subheader("📋 Scanned Ports Table")
    
    display_results = results if show_closed else [r for r in results if r.status == "open"]
    
    if not display_results:
        st.warning("No ports matched the current view criteria (no open ports detected). Enable 'Show Closed & Filtered Ports' in sidebar to inspect all scanned ports.")
    else:
        table_data = []
        for item in display_results:
            status_icon = "🟢 Open" if item.status == "open" else ("🟡 Filtered" if item.status == "filtered" else "🔴 Closed")
            table_data.append({
                "Port": item.port,
                "Status": status_icon,
                "Service": item.service,
                "Latency (ms)": f"{item.latency_ms:.2f}" if item.latency_ms is not None else "-",
                "Service Banner": item.banner or "-",
                "Error": item.error or "-",
            })
            
        df_table = pd.DataFrame(table_data)
        
        # Search filter
        search_query = st.text_input("🔍 Search table by port, service, or status...", value="")
        if search_query:
            q = search_query.lower()
            df_table = df_table[
                df_table["Port"].astype(str).str.contains(q)
                | df_table["Service"].str.lower().str.contains(q)
                | df_table["Status"].str.lower().str.contains(q)
                | df_table["Service Banner"].str.lower().str.contains(q)
            ]
            
        st.dataframe(
            df_table,
            column_config={
                "Port": st.column_config.NumberColumn("Port Number", format="%d"),
                "Status": st.column_config.TextColumn("Status"),
                "Service": st.column_config.TextColumn("Service Name"),
                "Latency (ms)": st.column_config.TextColumn("Latency (ms)"),
                "Service Banner": st.column_config.TextColumn("Banner / Identification"),
                "Error": st.column_config.TextColumn("Error / Reason"),
            },
            hide_index=True,
            use_container_width=True,
        )

    # Export Options
    st.subheader("💾 Export Scan Results")
    
    payload = build_payload(
        target=target_name,
        resolved_target=target_ip,
        ports=data["requested_ports"],
        results=results,
        elapsed_seconds=elapsed,
        os_info=os_info,
        banner_enabled=data["grab_banners"],
    )
    
    ex1, ex2, ex3 = st.columns(3)
    with ex1:
        st.download_button(
            label="📄 Download JSON Payload",
            data=json.dumps(payload, indent=2),
            file_name=f"netprobe_{target_ip}_results.json",
            mime="application/json",
            use_container_width=True,
        )
    with ex2:
        # Generate CSV
        csv_buffer = io.StringIO()
        df_export = pd.DataFrame([
            {
                "target": item.target,
                "port": item.port,
                "status": item.status,
                "service": item.service,
                "latency_ms": item.latency_ms,
                "banner": item.banner,
                "error": item.error,
            }
            for item in results
        ])
        df_export.to_csv(csv_buffer, index=False)
        st.download_button(
            label="📊 Download CSV Report",
            data=csv_buffer.getvalue(),
            file_name=f"netprobe_{target_ip}_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with ex3:
        # Generate Text
        lines = [
            "NetProbe Scan Results",
            f"Target: {target_name} ({target_ip})",
            f"Elapsed: {elapsed:.2f}s",
            f"Summary: {open_count} open, {closed_count} closed, {filtered_count} filtered",
            "",
            "Ports:",
        ]
        for item in results:
            b_str = f" banner={item.banner}" if item.banner else ""
            e_str = f" error={item.error}" if item.error else ""
            lines.append(f"- {item.port}/tcp {item.status} service={item.service} latency_ms={item.latency_ms}{b_str}{e_str}")
        if os_info:
            lines.extend([
                "",
                f"OS fingerprint: {os_info.probable_os} ({os_info.confidence} confidence)",
            ])
            if os_info.ttl is not None:
                lines.append(f"TTL observed: {os_info.ttl}")
            lines.extend(f"- {sig}" for sig in os_info.signals)
            
        txt_content = "\n".join(lines) + "\n"
        st.download_button(
            label="📝 Download Text Summary",
            data=txt_content,
            file_name=f"netprobe_{target_ip}_results.txt",
            mime="text/plain",
            use_container_width=True,
        )
else:
    st.info("👈 Configure your target and port options in the sidebar, then click **Launch NetProbe Scan** to begin reconnaissance.")
