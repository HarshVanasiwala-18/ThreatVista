import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import json
from collections import Counter

# Load the data
with open(r'Data Collection/malware_threat_data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Convert the data to a DataFrame
df = pd.DataFrame(data['Lazarus Group'])

# Convert 'Date' to datetime
df['Date'] = pd.to_datetime(df['Date'])

# Extract year and month
df['Year'] = df['Date'].dt.year
df['Month'] = df['Date'].dt.month
df['YearMonth'] = df['Date'].dt.to_period('M')

# Function to create visualizations
def create_visualizations():
    st.title("Malware Threat Data Analysis")

    # Visualize the number of reports per year
    st.subheader("Number of Reports per Year")
    yearly_counts = df['Year'].value_counts().sort_index()
    fig = px.bar(yearly_counts, x=yearly_counts.index, y=yearly_counts.values, labels={'x': 'Year', 'y': 'Number of Reports'}, title="Number of Reports per Year")
    st.plotly_chart(fig)

    # Distribution of Threat Actors
    st.subheader("Distribution of Threat Actors")
    threat_actors = df['Threat Actor'].value_counts().head(10)
    fig = px.bar(threat_actors, x=threat_actors.index, y=threat_actors.values, labels={'x': 'Threat Actor', 'y': 'Number of Reports'}, title="Distribution of Threat Actors")
    st.plotly_chart(fig)

    # Distribution of CVEs
    st.subheader("Distribution of CVEs")
    cves = [cve for cves in df['CVE IDs'].dropna() for cve in cves]
    cve_counts = pd.Series(Counter(cves)).sort_values(ascending=False).head(10)
    fig = px.bar(cve_counts, x=cve_counts.index, y=cve_counts.values, labels={'x': 'CVE', 'y': 'Frequency'}, title="Distribution of CVEs")
    st.plotly_chart(fig)

    # Malware trend over time
    st.subheader("Malware Trend Over Time")
    malware_trend = df.groupby('YearMonth').size().reset_index(name='count')
    malware_trend['YearMonth'] = malware_trend['YearMonth'].astype(str)
    fig = px.line(malware_trend, x='YearMonth', y='count', labels={'YearMonth': 'Year-Month', 'count': 'Number of Reports'}, title="Malware Trend Over Time", markers=True)
    st.plotly_chart(fig)

    # Heatmap of malware activity by month and year
    st.subheader("Heatmap of Malware Activity")
    heatmap_data = df.groupby(['Year', 'Month']).size().unstack().fillna(0)
    fig = go.Figure(data=go.Heatmap(z=heatmap_data.values, x=heatmap_data.columns, y=heatmap_data.index, colorscale='YlOrRd'))
    fig.update_layout(title='Heatmap of Malware Activity', xaxis_nticks=12)
    st.plotly_chart(fig)

# Function to explore threat actors and malware
def explore_threat_actors_malware():
    st.title("Explore Threat Actors and Malware")

    # Load additional data
    with open(r'Data Collection/threat_actors.json', 'r', encoding='utf-8') as f:
        threat_actor_data = json.load(f)
    with open(r'Data Collection/threat_actor_data.json', 'r', encoding='utf-8') as f:
        threat_actor_details = json.load(f)
    with open(r'Data Collection/malware_families.json', 'r', encoding='utf-8') as f:
        malware_families_data = json.load(f)
    with open(r'Data Collection/malware_family_data.json', 'r', encoding='utf-8') as f:
        malware_family_details = json.load(f)

    # Convert lists to dictionaries for easier selection
    threat_actor_dict = {actor['Threat Actor']: actor for actor in threat_actor_data}
    malware_family = {family['Malware Family']: family for family in malware_families_data}

    # Selectbox for choosing an item
    item_type = st.selectbox("Select Type", ["Threat Actor", "Malware"])
    if item_type == "Threat Actor":
        selected_item = st.selectbox("Select a Threat Actor", list(threat_actor_dict.keys()))
        details = threat_actor_details.get(selected_item, [])
    else:
        # selected_item = st.selectbox("Select a Malware", list(malware_families_dict.keys()))
        # details = malware_family_details.get(selected_item, [])
        selected_item = st.selectbox("Select a Malware", list(malware_family.keys()))
        show_details = malware_family[selected_item]['Name']
        details = malware_family_details.get(show_details, [])

    # Check if 'Date' exists in the details
    if not details or 'Date' not in pd.DataFrame(details).columns:
        st.error(f"No 'Date' column found in details for {selected_item}")
        return

    # Display the report trend for the selected item
    st.subheader(f"Report Trend for {item_type}: {selected_item}")
    trend_df = pd.DataFrame(details)
    trend_df['Date'] = pd.to_datetime(trend_df['Date'])
    trend_df['YearMonth'] = trend_df['Date'].dt.to_period('M')
    trend = trend_df.groupby('YearMonth').size().reset_index(name='count')
    trend['YearMonth'] = trend['YearMonth'].astype(str)
    fig = px.line(trend, x='YearMonth', y='count', labels={'YearMonth': 'Year-Month', 'count': 'Number of Reports'}, title=f"Report Trend for {item_type}: {selected_item}", markers=True)
    st.plotly_chart(fig)

    # Display additional information
    st.subheader(f"Additional Information for {item_type}: {selected_item}")
    st.write(trend_df[['Date', 'Title', 'Organization', 'Author', 'URL']].reset_index(drop=True))

# Function to display data source information
def data_source_info():
    st.title("Data Source Information")
    st.write("""
    This application uses data from [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/).
    Malpedia is an excellent resource for malware analysis, providing detailed information on various threat actors and malware families.
    
    This application is developed for project purposes only.
    """)

# Main app
def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Data Analysis", "Explore Threat Actors and Malware", "Data Source Information"])

    if page == "Data Analysis":
        create_visualizations()
    elif page == "Explore Threat Actors and Malware":
        explore_threat_actors_malware()
    elif page == "Data Source Information":
        data_source_info()

if __name__ == "__main__":
    main()
