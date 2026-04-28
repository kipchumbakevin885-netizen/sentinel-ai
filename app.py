# ----------------------------
# EXPLAINABILITY (STACKED)
# ----------------------------
st.subheader("🧠 AI Explainability (Stacked Impact View)")

if hasattr(model, "feature_importances_"):
    importances = model.feature_importances_
    selected_features = feature_names[selector.get_support()]

    imp_df = pd.DataFrame({
        "Feature": selected_features,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False).head(10)

    # OPTIONAL: show only active permissions
    imp_df = imp_df[imp_df["Feature"].isin(active)]

    # Normalize values
    if len(imp_df) > 0:
        imp_df["Normalized"] = imp_df["Importance"] / imp_df["Importance"].sum()

        st.markdown("**Top Risk Contributors (Stacked)**")

        fig, ax = plt.subplots(figsize=(10, 2))

        left = 0
        for _, row in imp_df.iterrows():
            ax.barh(
                ["Total Impact"],
                row["Normalized"],
                left=left,
                label=f"{row['Feature']} ({row['Normalized']*100:.1f}%)"
            )
            left += row["Normalized"]

        ax.set_xlim(0, 1)
        ax.set_xlabel("Contribution to Prediction")
        ax.set_title("Stacked Feature Contribution")

        ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

        st.pyplot(fig)
    else:
        st.info("No active features contributing to risk")

else:
    st.info("Model does not support feature importance")
