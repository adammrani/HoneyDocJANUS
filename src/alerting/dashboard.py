"""
src/alerting/dashboard.py
Streamlit dashboard for the standalone honeydoc server.

Three pages (sidebar radio):
  🔴 Alertes         — real-time alerts + metrics, auto-refresh every 10s
  📄 HoneyDocs actifs — deployed decoys
  ⚙️ Générer          — form that POSTs /generate_decoy

Importing this module never launches the UI: the UI runs only under
`streamlit run` (when __name__ == "__main__"). No browser storage is used.
"""

import os
import time

import requests
import streamlit as st

API_URL = os.getenv("CALLBACK_BASE_URL", "http://localhost:8000")
ADMIN_API_KEY = os.getenv("JANUS_ADMIN_API_KEY", "")
REFRESH_SECONDS = 10

FORMAT_OPTIONS = {
    "financial_report": ["docx", "xlsx", "csv", "json"],
    "hr_document": ["docx", "csv", "json"],
    "technical_config": ["docx", "env", "yaml", "json", "zip"],
    "cloud_credentials": ["env", "yaml", "json", "zip"],
}


# ── API helpers (never raise: return (data, error)) ──────

def _api_get(path: str):
    try:
        resp = requests.get(f"{API_URL}{path}", headers=_api_headers(), timeout=5)
        resp.raise_for_status()
        return resp.json(), None
    except requests.RequestException as exc:
        return None, str(exc)


def _api_post(path: str, payload: dict):
    try:
        resp = requests.post(
            f"{API_URL}{path}",
            json=payload,
            headers=_api_headers(),
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json(), None
    except requests.RequestException as exc:
        return None, str(exc)


def _api_headers() -> dict[str, str]:
    return {"X-JANUS-API-Key": ADMIN_API_KEY} if ADMIN_API_KEY else {}


# ── Pages ────────────────────────────────────────────────

def page_alerts() -> None:
    st.header("🔴 Alertes en temps réel")
    alerts, error = _api_get("/alerts?limit=200")

    if error:
        st.error(f"API indisponible : {error}")
        st.info("Lancez le serveur avec `python main.py` puis rechargez.")
        return

    alerts = alerts or []
    llm_agents = [a for a in alerts if str(a.get("token_id", "")).startswith("CI1_")]
    unique_ips = {a.get("src_ip") for a in alerts if a.get("src_ip")}
    countries = {a.get("geo_country") for a in alerts if a.get("geo_country")}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alertes totales", len(alerts))
    c2.metric("Agents LLM (CI1)", len(llm_agents))
    c3.metric("IPs uniques", len(unique_ips))
    c4.metric("Pays sources", len(countries))

    if not alerts:
        st.info("Aucune alerte pour le moment. Le système attend un déclenchement.")
    else:
        rows = [
            {
                "Horodatage": a.get("triggered_at", ""),
                "Fichier": a.get("honeydoc_filename") or "-",
                "IP": a.get("src_ip") or "-",
                "Pays": a.get("geo_country") or "-",
                "Ville": a.get("geo_city") or "-",
                "OS déclaré/estimé": a.get("os_guess") or "Inconnu",
                "Source OS": a.get("os_evidence_source") or "none",
                "Confiance OS": a.get("os_confidence") or "none",
                "Outil / Navigateur": a.get("browser_guess") or "-",
            }
            for a in alerts
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

        with st.expander("🔎 Détail de la dernière alerte"):
            st.json(alerts[0])

    time.sleep(REFRESH_SECONDS)
    st.rerun()


def page_honeydocs() -> None:
    st.header("📄 HoneyDocs déployés")
    docs, error = _api_get("/honeydocs")

    if error:
        st.error(f"API indisponible : {error}")
        return

    docs = docs or []
    if not docs:
        st.info("Aucun HoneyDoc déployé. Utilisez la page « Générer ».")
        return

    rows = [
        {
            "ID": d.get("id"),
            "Fichier": d.get("filename"),
            "Type": d.get("doc_type"),
            "Format": d.get("file_format") or "docx",
            "Scénario": d.get("scenario") or "-",
            "Répertoire cible": d.get("target_dir") or "(local)",
            "Créé le": d.get("created_at"),
            "TTL (h)": d.get("ttl_hours"),
            "Actif": "✅" if d.get("active") else "⛔",
        }
        for d in docs
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def page_generate() -> None:
    st.header("⚙️ Générer un HoneyDoc")

    with st.form("generate_form"):
        doc_type = st.selectbox(
            "Type de document",
            list(FORMAT_OPTIONS),
        )
        output_format = st.selectbox("Format", FORMAT_OPTIONS[doc_type])
        target_dir = st.text_input(
            "Sous-dossier cible (laisser vide = data/shared)", ""
        )
        ttl_hours = st.slider("Durée de vie (heures)", 1, 168, 72)
        col1, col2 = st.columns(2)
        enable_janus = col1.toggle("Activer JANUS (CI1)", value=True)
        enable_ci3 = col2.toggle("Activer CI3 (credentials)", value=True)
        submitted = st.form_submit_button("🚀 Générer le HoneyDoc", type="primary")

    if submitted:
        with st.spinner("Génération en cours..."):
            result, error = _api_post(
                "/generate_decoy",
                {
                    "doc_type": doc_type,
                    "output_format": output_format,
                    "target_dir": target_dir,
                    "ttl_hours": ttl_hours,
                    "enable_janus": enable_janus,
                    "enable_ci3": enable_ci3,
                },
            )
        if error:
            st.error(f"Échec de la génération : {error}")
        else:
            st.success(result.get("message", "HoneyDoc généré."))
            st.code(
                f"Fichier   : {result.get('filename')}\n"
                f"Chemin     : {result.get('deployed_path')}\n"
                f"Token URL  : {result.get('token_url')}",
                language="text",
            )


def page_wazuh() -> None:
    st.header("🛡️ Wazuh et télémétrie")
    status, status_error = _api_get("/wazuh/status")
    telemetry, telemetry_error = _api_get("/telemetry/status")

    if status_error or telemetry_error:
        st.error(f"API indisponible : {status_error or telemetry_error}")
        return

    left, right = st.columns(2)
    left.subheader("Collecteur de détections")
    left.json(status)
    right.subheader("Collecteur forensique")
    right.json(telemetry)

    detections, error = _api_get("/wazuh/detections?limit=100")
    if error:
        st.warning(f"Détections indisponibles : {error}")
    elif detections:
        st.subheader("Dernières détections corrélées")
        st.dataframe(detections, use_container_width=True, hide_index=True)
    else:
        st.info("Aucune détection Wazuh persistée pour le moment.")


def main() -> None:
    st.set_page_config(page_title="Honey-Documents", page_icon="🍯", layout="wide")
    st.sidebar.title("🍯 Honey-Documents")
    st.sidebar.caption(f"API : {API_URL}")
    page = st.sidebar.radio(
        "Navigation",
        ["🔴 Alertes", "📄 HoneyDocs actifs", "🛡️ Wazuh", "⚙️ Générer"],
    )

    if page == "🔴 Alertes":
        page_alerts()
    elif page == "📄 HoneyDocs actifs":
        page_honeydocs()
    elif page == "🛡️ Wazuh":
        page_wazuh()
    else:
        page_generate()


if __name__ == "__main__":
    main()
