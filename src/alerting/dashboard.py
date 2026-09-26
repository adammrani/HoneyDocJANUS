"""Streamlit dashboard for the standalone HoneyDoc server."""

import os
from pathlib import Path

import requests
import streamlit as st
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_URL = os.getenv("CALLBACK_BASE_URL", "http://localhost:8000")
ADMIN_API_KEY = os.getenv("JANUS_ADMIN_API_KEY", "")
REFRESH_SECONDS = 5

FORMAT_OPTIONS = {
    "financial_report": ["docx", "xlsx", "csv", "json"],
    "hr_document": ["docx", "csv", "json"],
    "technical_config": ["docx", "env", "yaml", "json", "zip"],
    "cloud_credentials": ["env", "yaml", "json", "zip"],
}


def _api_headers() -> dict[str, str]:
    return {"X-JANUS-API-Key": ADMIN_API_KEY} if ADMIN_API_KEY else {}


def _api_get(path: str):
    try:
        response = requests.get(
            f"{API_URL}{path}",
            headers=_api_headers(),
            timeout=5,
        )
        response.raise_for_status()
        return response.json(), None
    except requests.RequestException as exc:
        return None, str(exc)


def _api_post(path: str, payload: dict):
    try:
        response = requests.post(
            f"{API_URL}{path}",
            json=payload,
            headers=_api_headers(),
            timeout=60,
        )
        response.raise_for_status()
        return response.json(), None
    except requests.RequestException as exc:
        return None, str(exc)


def _activation_explanation(token_type: str, output_format: str) -> str:
    if token_type == "aws_keys":
        return (
            "Wazuh détecte la lecture locale. Le Canarytoken distant se déclenche "
            "uniquement lorsque les clés sont présentées à une API AWS."
        )
    if token_type in {"ms_word", "ms_excel"}:
        return (
            "Wazuh détecte l'accès local. Le Canarytoken Office tente un appel "
            "réseau à l'ouverture, si Office autorise le contenu externe."
        )
    if output_format in {"csv", "json", "yaml", "env", "zip"}:
        return (
            "Wazuh détecte l'accès local. Ce format texte ne lance pas de réseau "
            "tout seul : le Canarytoken distant exige l'utilisation du lien inclus."
        )
    return "Le déclenchement dépend du capteur associé à ce format."


def _wazuh_rows(detections: list[dict]) -> list[dict]:
    return [
        {
            "Horodatage": detection.get("observed_at"),
            "HoneyDoc": detection.get("honeydoc_id"),
            "Règle Wazuh": detection.get("wazuh_rule_id") or "-",
            "Action": detection.get("action") or "unknown",
            "Fichier": detection.get("object_path") or "-",
            "Processus": detection.get("process_name") or "-",
            "Utilisateur": detection.get("username") or "-",
            "Niveau": detection.get("verdict_level") or "-",
        }
        for detection in detections
    ]


@st.fragment(run_every=REFRESH_SECONDS)
def page_alerts() -> None:
    st.header("🔴 Signaux JANUS en temps réel")

    canary_alerts, canary_error = _api_get("/alerts?limit=200")
    wazuh_detections, wazuh_error = _api_get(
        "/wazuh/detections?limit=200&matched_only=true"
    )
    canary_status, _ = _api_get("/canary/status")

    if canary_error and wazuh_error:
        st.error(f"API indisponible : {canary_error}")
        st.info("Lancez le serveur avec `python main.py` puis rechargez.")
        return

    canary_alerts = canary_alerts or []
    wazuh_detections = [
        detection
        for detection in (wazuh_detections or [])
        if detection.get("detected") and not detection.get("suppressed")
    ]
    unique_ips = {
        alert.get("src_ip") for alert in canary_alerts if alert.get("src_ip")
    }

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Signaux totaux", len(wazuh_detections) + len(canary_alerts))
    c2.metric("Détections Wazuh", len(wazuh_detections))
    c3.metric("Callbacks Canary reçus", len(canary_alerts))
    c4.metric("IPs distantes observées", len(unique_ips))

    st.caption(
        f"Actualisation automatique toutes les {REFRESH_SECONDS} secondes. "
        "Un événement Wazuh peut demander quelques secondes pour traverser "
        "Windows, l'agent, l'Indexer et JANUS."
    )

    st.subheader("Détections locales Wazuh")
    if wazuh_error:
        st.warning(f"Détections Wazuh indisponibles : {wazuh_error}")
    elif wazuh_detections:
        st.dataframe(
            _wazuh_rows(wazuh_detections),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Aucune interaction HoneyDoc corrélée par Wazuh pour le moment.")

    st.subheader("Callbacks Canarytokens reçus par JANUS")
    if canary_status and not canary_status.get("webhook_enabled"):
        st.info(
            "Le fournisseur public est configuré en e-mail uniquement. Les e-mails "
            "Canarytokens ne sont donc pas recopiés dans JANUS ; cette section reste "
            "vide même lorsqu'un e-mail a bien été reçu."
        )
    if canary_error:
        st.warning(f"Callbacks Canary indisponibles : {canary_error}")
    elif not canary_alerts:
        st.caption("Aucun callback Canarytokens enregistré dans la base JANUS.")
    else:
        rows = [
            {
                "Horodatage": alert.get("triggered_at", ""),
                "Fichier": alert.get("honeydoc_filename") or "-",
                "IP": alert.get("src_ip") or "-",
                "Pays": alert.get("geo_country") or "-",
                "Ville": alert.get("geo_city") or "-",
                "OS déclaré/estimé": alert.get("os_guess") or "Inconnu",
                "Confiance OS": alert.get("os_confidence") or "none",
                "Outil / Navigateur": alert.get("browser_guess") or "-",
            }
            for alert in canary_alerts
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        with st.expander("Détail de la dernière alerte Canary"):
            st.json(canary_alerts[0])

def page_honeydocs() -> None:
    st.header("📄 HoneyDocs déployés")
    documents, error = _api_get("/honeydocs")

    if error:
        st.error(f"API indisponible : {error}")
        return

    documents = documents or []
    retired_count = sum(1 for document in documents if not document.get("active"))
    documents = [document for document in documents if document.get("active")]
    if not documents:
        st.info("Aucun HoneyDoc actif. Utilisez la page « Générer ».")
        return

    if retired_count:
        st.caption(
            f"{retired_count} HoneyDoc(s) retiré(s) restent dans l'historique SQLite."
        )

    rows = [
        {
            "ID": document.get("id"),
            "Fichier": document.get("filename"),
            "Type": document.get("doc_type"),
            "Format": document.get("file_format") or "docx",
            "Fournisseur": document.get("token_provider") or "-",
            "Type Canary": document.get("token_type") or "-",
            "Activation distante": document.get("token_activation") or "-",
            "Scénario": document.get("scenario") or "-",
            "Créé le": document.get("created_at"),
            "TTL (h)": document.get("ttl_hours"),
        }
        for document in documents
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def page_generate() -> None:
    st.header("⚙️ Générer un HoneyDoc")

    # These dependent choices deliberately live outside the form. Streamlit
    # forms batch widget changes, which previously allowed a stale DOCX value
    # to be submitted after the user had selected JSON.
    doc_type = st.selectbox(
        "Type de document",
        list(FORMAT_OPTIONS),
        key="generate_doc_type",
    )
    output_format = st.selectbox(
        "Format",
        FORMAT_OPTIONS[doc_type],
        key=f"generate_output_format_{doc_type}",
    )

    expected_token_type = (
        "aws_keys"
        if doc_type == "cloud_credentials"
        else "ms_word"
        if output_format == "docx"
        else "ms_excel"
        if output_format == "xlsx"
        else "web"
    )
    st.caption(_activation_explanation(expected_token_type, output_format))

    with st.form("generate_form"):
        target_dir = st.text_input(
            "Sous-dossier cible (laisser vide = data/shared)",
            "",
        )
        ttl_hours = st.slider("Durée de vie (heures)", 1, 168, 72)
        submitted = st.form_submit_button(
            "🚀 Générer le HoneyDoc",
            type="primary",
        )

    if not submitted:
        return

    with st.spinner("Génération en cours..."):
        result, error = _api_post(
            "/generate_decoy",
            {
                "doc_type": doc_type,
                "output_format": output_format,
                "target_dir": target_dir,
                "ttl_hours": ttl_hours,
                "enable_janus": False,
                "enable_ci3": False,
            },
        )

    if error:
        st.error(f"Échec de la génération : {error}")
        return

    actual_format = result.get("file_format")
    if actual_format != output_format:
        st.error(
            f"Incohérence bloquante : format demandé={output_format}, "
            f"format produit={actual_format}."
        )
        return

    st.success(result.get("message", "HoneyDoc généré."))
    lines = [
        f"Fichier       : {result.get('filename')}",
        f"Format        : {actual_format}",
        f"Chemin        : {result.get('deployed_path')}",
        f"SHA-256       : {result.get('sha256')}",
        f"Fournisseur   : {result.get('token_provider')}",
        f"Type de token : {result.get('token_type')}",
        f"Activation    : {result.get('token_activation')}",
        "Capteurs       : " + ", ".join(result.get("detection_layers") or []),
    ]
    if result.get("token_type") != "aws_keys":
        lines.append(f"URL du token  : {result.get('token_url')}")
    st.code("\n".join(lines), language="text")
    st.info(
        _activation_explanation(
            result.get("token_type", ""),
            actual_format or output_format,
        )
    )


def page_wazuh() -> None:
    st.header("🛡️ Wazuh et télémétrie")
    st.button("Actualiser maintenant")
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

    detections, error = _api_get(
        "/wazuh/detections?limit=100&matched_only=true"
    )
    detections = [
        detection
        for detection in (detections or [])
        if detection.get("detected") and not detection.get("suppressed")
    ]
    if error:
        st.warning(f"Détections indisponibles : {error}")
    elif detections:
        st.subheader("Dernières détections corrélées")
        st.dataframe(
            _wazuh_rows(detections),
            use_container_width=True,
            hide_index=True,
        )
        with st.expander("Détail brut de la dernière détection"):
            st.warning(
                "Le JSON Wazuh peut contenir une ligne de commande ou un chemin sensible."
            )
            st.json(detections[0])
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
