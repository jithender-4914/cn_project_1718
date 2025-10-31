import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def create_visualization(df: pd.DataFrame) -> None:
    """📊 Create all dynamic dashboard visualizations"""
    st.markdown("### 🌐 Real-Time Network Traffic Dashboard")

    # ---- 🧩 Handle Empty Data ----
    if df.empty:
        st.warning("⚠️ No data available yet. Waiting for packets...")
        return

    # ---- 🕒 Timestamp Conversion ----
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
    except Exception as e:
        st.error(f"Timestamp conversion failed: {e}")
        return

    # ---- 1️⃣ Protocol Distribution (Pie Chart) ----
    st.subheader("1️⃣ Protocol Distribution")
    protocol_counts = df['protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    fig_protocol = px.pie(
        protocol_counts,
        names='Protocol',
        values='Count',
        title='Protocol Distribution (Live)',
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    st.plotly_chart(fig_protocol, use_container_width=True)

    # ---- 2️⃣ Packets per Second (Line Chart) ----
    st.subheader("2️⃣ Packets per Second (Real-Time Trend)")
    df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size().reset_index(name='Packet Count')
    fig_timeline = px.line(
        df_grouped,
        x='timestamp',
        y='Packet Count',
        title='Packets per Second (Real-Time)',
        markers=True,
        line_shape='spline'
    )
    fig_timeline.update_traces(line=dict(width=2))
    st.plotly_chart(fig_timeline, use_container_width=True)

    # ---- 3️⃣ Average Packet Size per Protocol (Bar Chart) ----
    st.subheader("3️⃣ Average Packet Size by Protocol")
    avg_size = df.groupby('protocol')['size'].mean().reset_index()
    fig_size = go.Figure(
        data=[
            go.Bar(
                x=avg_size['protocol'],
                y=avg_size['size'],
                text=[f"{s:.1f} bytes" for s in avg_size['size']],
                textposition='auto',
                marker_color=px.colors.qualitative.Safe
            )
        ]
    )
    fig_size.update_layout(
        title='Average Packet Size by Protocol',
        xaxis_title='Protocol',
        yaxis_title='Average Size (bytes)',
        bargap=0.3
    )
    st.plotly_chart(fig_size, use_container_width=True)

    # ---- 4️⃣ Top Talkers (Optional Table) ----
    if 'source' in df.columns:
        st.subheader("4️⃣ Top Source IPs (By Packet Count)")
        top_sources = df['source'].value_counts().head(10).reset_index()
        top_sources.columns = ['Source IP', 'Packet Count']
        st.dataframe(top_sources, use_container_width=True)

    st.success("✅ Dashboard updated successfully!")

# Example usage:
# df = pd.read_csv("network_data.csv")
# create_visualization(df)
