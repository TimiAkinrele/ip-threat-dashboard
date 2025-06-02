import streamlit as st
import pandas as pd
import requests
import time
from check_ip import check_ip, is_valid_ip

# ---------------------------------------
# OPTIONAL: Get IP location using ip-api
# ---------------------------------------
def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            return {
                'lat': data['lat'],
                'lon': data['lon'],
                'city': data['city'],
                'country': data['countryCode']
            }
    except:
        pass
    return None

# ---------------------------------------
# Color-coded threat indicators
# ---------------------------------------
def highlight_risk(row):
    score = row['Abuse Score']
    if score >= 80:
        return ['background-color: red'] * len(row)
    elif score >= 40:
        return ['background-color: orange'] * len(row)
    elif score > 0:
        return ['background-color: yellow'] * len(row)
    else:
        return ['background-color: grey'] * len(row)

# ---------------------------------------
# Streamlit UI
# ---------------------------------------
st.set_page_config(page_title="IP Threat Dashboard", layout="centered")
st.title("🛡️ IP Threat Intelligence Dashboard")
st.caption("Built with Streamlit • AbuseIPDB • GeoIP • Python 💻")


# ---------------------------------------
# SINGLE IP LOOKUP
# ---------------------------------------
st.header("🔎 Single IP Lookup")
ip = st.text_input("Enter an IP address:")

if ip:
    if is_valid_ip(ip):
        result = check_ip(ip)
        if result:
            st.success("✅ Lookup complete!")
            single_result = {
                "IP": result['ipAddress'],
                "Abuse Score": result['abuseConfidenceScore'],
                "Country": result['countryCode'],
                "ISP": result['isp'],
                "Reports": result['totalReports'],
                "Last Seen": result['lastReportedAt']
            }
            st.write(single_result)
    else:
        st.error("❌ Invalid IP address.")

# ---------------------------------------
# BATCH SCAN
# ---------------------------------------
st.markdown("---")
st.header("📂 Batch Scan from File")

uploaded_file = st.file_uploader("Upload a `.txt` file with one IP per line", type=["txt"])

if uploaded_file is not None:
    content = uploaded_file.read().decode("utf-8")
    ip_list = [line.strip() for line in content.splitlines() if line.strip()]

    st.info(f"🔍 Scanning {len(ip_list)} IPs...")

    results = []

    for i, ip in enumerate(ip_list):
        if not is_valid_ip(ip):
            st.warning(f"⚠️ Invalid IP skipped: {ip}")
            continue

        result = check_ip(ip)
        if result:
            location = get_ip_location(ip)
            results.append({
                "IP": result['ipAddress'],
                "Abuse Score": result['abuseConfidenceScore'],
                "Country": result['countryCode'],
                "ISP": result['isp'],
                "Reports": result['totalReports'],
                "Last Seen": result['lastReportedAt'],
                "City": location['city'] if location else None,
                "Latitude": location['lat'] if location else None,
                "Longitude": location['lon'] if location else None
            })
        time.sleep(1)

    if results:
        df = pd.DataFrame(results)
        st.success("✅ Batch scan complete.")
        styled_df = df.style.apply(highlight_risk, axis=1)
        st.dataframe(styled_df, use_container_width=True)

        # 🌍 Geo map
        st.subheader("🌍 Threat Origin Map")
        map_df = df[["Latitude", "Longitude"]].dropna()
        map_df = map_df.rename(columns={"Latitude": "latitude", "Longitude": "longitude"})
        if not map_df.empty:
            st.map(map_df)
        else:
            st.info("No geolocation data available for mapping.")

        # 📥 Download CSV
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV Report",
            data=csv,
            file_name='ip_threat_report.csv',
            mime='text/csv'
        )
