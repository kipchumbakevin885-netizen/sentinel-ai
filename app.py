# --- 4. TACTICAL SCANNER ---
st.write("### 📡 REAL-TIME PERMISSION SCANNER")
with st.container():
    st.write("Toggle application permissions for instant behavioral analysis:")
    
    # Create grid for checkboxes
    cols = st.columns(4)
    user_input = []
    
    for i, feature in enumerate(feature_names):
        with cols[i % 4]:
            val = st.checkbox(feature.replace("_", " "), key=feature)
            user_input.append(1 if val else 0)

    if st.button("🚀 EXECUTE NEURAL SCAN"):
        input_vector = np.array([user_input])
        prediction = model.predict(input_vector)[0]
        prob = model.predict_proba(input_vector)[0][1]

        # Results Display
        res_col1, res_col2 = st.columns(2)
        with res_col1:
            if prediction == 1:
                st.error(f"☢️ THREAT DETECTED: {prob:.2%}")
            else:
                st.success(f"🛡️ KERNEL SAFE: {1-prob:.2%}")
        
        with res_col2:
            st.progress(prob)
