import streamlit as st
import pandas as pd
import time
from lib.malware_logic import predict  # Assume your logic is here

# 1. Page Configuration (The "Sentinel" Look)
st.set_page_config(page_title="Sentinel AI | Tech Titans", page_icon="🛡️", layout="centered")

# Custom CSS to mimic your React styling
st.markdown("""
    <style>
    .text-gradient {
        background: linear-gradient(90deg, #00f2ff, #0070ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: bold;
    }
    .stApp { background-color: #05070a; color: #a1a1aa; }
    .css-1offfwp { background-color: rgba(255, 255, 255, 0.05); border-radius: 15px; padding: 20px; }
    </style>
    """, unsafe_allow_html=True)

# 2. Header
col1, col2 = st.columns([1, 4])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/1085/1085750.png", width=60) # Shield Icon
with col2:
    st.markdown("## Sentinel AI")
    st.caption("Android Malware Detection · Tech Titans Unit")

st.divider()

# 3. Main Hero Section
st.markdown("<h1 style='text-align: center;'>Detect Android malware in <span class='text-gradient'>seconds</span></h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: 1.2em;'>Upload an app's permission profile and our model classifies it as safe or malicious with a full risk breakdown.</p>", unsafe_allow_html=True)

# 4. Upload Zone
uploaded_file = st.file_uploader("", type="csv", help="Upload an app's permission manifest in CSV format")

# 5. Analysis Logic (Matches your React 'analyze' function)
if uploaded_file is not None:
    file_details = {"FileName": uploaded_file.name, "FileType": uploaded_file.type}
    
    # "Analyzing" state
    with st.status("🛡️ Scanning permissions and computing risk score...", expanded=True) as status:
        try:
            # Simulated inference latency for the "scanning" feel
            df = pd.read_csv(uploaded_file)
            time.sleep(1.2) # Mimics your 700ms - 1s timeout
            
            # Logic Placeholder
            # result = predict(df) 
            risk_score = 0.85 # Example
            
            status.update(label="✅ Analysis complete!", state="complete", expanded=False)
            
            # 6. Result Dashboard
            st.toast(f"Analysis complete: Evaluation Finished", icon="✅")
            
            res_col1, res_col2 = st.columns(2)
            with res_col1:
                st.metric("Risk Score", f"{risk_score*100}%", delta="-5%" if risk_score < 0.5 else "HIGH")
            with res_col2:
                if risk_score > 0.7:
                    st.error("🚨 THREAT DETECTED")
                else:
                    st.success("✅ INTEGRITY VERIFIED")
                    
        except Exception as e:
            st.error(f"Could not parse CSV: {e}")

# 7. Footer
st.markdown("---")
st.markdown("<p style='text-align: center; font-size: 0.8em; color: gray;'>Built with Python & Streamlit · Tech Titans Strategic Defense Unit</p>", unsafe_allow_html=True)
