"""Dashboard non technique de JANUS, construit avec Streamlit."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any

import requests
import streamlit as st


API_URL = os.getenv("JANUS_API_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_KEY = os.getenv("JANUS_ADMIN_API_KEY", "").strip()
WAZUH_SECRET = os.getenv("WAZUH_INGEST_SECRET", "").strip()
TIMEOUT = 20

MODE_LABELS = {
    "local_pixel": "Pixel JANUS local",
    "canary_remote": "Canary distant — URL existante",
    "dual": "Double capteur — JANUS + Canary",
    "canary_official": "Canarytokens officiel — création fournisseur",
}


def api_headers() -> dict[str, str]:
    return {"X-JANUS-API-Key": ADMIN_KEY} if ADMIN_KEY else {}


def api_get(path: str, *, raw: bool = False) -> tuple[Any, str | None]:
    try:
        response = requests.get(
            f"{API_URL}{path}", headers=api_headers(), timeout=TIMEOUT
        )
        response.raise_for_status()
        return (response.content if raw else response.json()), None
    except (requests.RequestException, ValueError) as error:
        return None, friendly_error(error)


def api_post(
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[Any, str | None]:
    selected_headers = {**api_headers(), **(headers or {})}
    try:
        response = requests.post(
            f"{API_URL}{path}",
            json=payload,
            headers=selected_headers,
            timeout=60,
        )
        if not response.ok:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = response.text
            return None, str(detail or f"Erreur HTTP {response.status_code}")
        return response.json(), None
    except (requests.RequestException, ValueError) as error:
        return None, friendly_error(error)


def friendly_error(error: Exception) -> str:
    text = str(error)
    if "Connection" in text or "connect" in text.casefold():
        return "Le service JANUS n'est pas joignable. Lancez-le avec python run.py."
    return text


def refresh_state() -> dict[str, Any]:
    state, error = api_get("/api/state")
    if error:
        st.error(error)
        return {
            "artifacts": [],
            "events": [],
            "counters": {},
            "connectors": {},
        }
    return state


def fmt_time(value: str | None) -> str:
    if not value:
        return "—"
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return moment.astimezone().strftime("%d/%m/%Y · %H:%M:%S")
    except ValueError:
        return value


def format_bytes(value: int | None) -> str:
    size = int(value or 0)
    return f"{size / 1024:.1f} Ko" if size >= 1024 else f"{size} o"


def connector_card(title: str, connector: dict[str, Any]) -> None:
    status = connector.get("status", "waiting")
    tone = "ok" if status in {"ready", "configured"} else "manual"
    st.markdown(
        f"""
        <div class="connector-card {tone}">
          <div class="eyebrow">{html.escape(status.upper())}</div>
          <h4>{html.escape(title)}</h4>
          <p>{html.escape(str(connector.get('proof') or 'En attente de configuration.'))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def header() -> None:
    st.markdown(
        """
        <div class="hero">
          <div>
            <span class="eyebrow">EVIDENCE HUB · PYTHON</span>
            <h1>JANUS</h1>
            <p>Déployer un document synthétique. Observer sans inventer.</p>
          </div>
          <div class="hero-mark"><span></span><span></span><span></span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_overview(state: dict[str, Any]) -> None:
    counters = state.get("counters", {})
    st.subheader("Vue d'ensemble")
    columns = st.columns(4)
    columns[0].metric("Honeydocs", counters.get("artifact_count", 0))
    columns[1].metric("Preuves reçues", counters.get("event_count", 0))
    columns[2].metric("Signaux forts", counters.get("strong_events", 0))
    columns[3].metric("Wazuh", counters.get("wazuh_events", 0))

    st.markdown("### Capteurs")
    connectors = state.get("connectors", {})
    cols = st.columns(4)
    with cols[0]:
        connector_card("Pixel JANUS", connectors.get("local_pixel", {}))
    with cols[1]:
        connector_card("Contenu", connectors.get("ai", {}))
    with cols[2]:
        connector_card("Canary", connectors.get("canary", {}))
    with cols[3]:
        connector_card("Wazuh", connectors.get("wazuh", {}))

    st.markdown("### Derniers artefacts")
    artifacts = state.get("artifacts", [])
    if not artifacts:
        st.info("Aucun honeydoc pour le moment. Ouvrez « Générer » pour créer le premier.")
        return
    rows = [
        {
            "Titre": item.get("title"),
            "Capteur": MODE_LABELS.get(item.get("sensor_mode"), item.get("sensor_mode")),
            "Contenu": item.get("content_mode"),
            "Événements": item.get("event_count", 0),
            "Créé": fmt_time(item.get("created_at")),
        }
        for item in artifacts[:20]
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def page_generate(state: dict[str, Any]) -> None:
    st.subheader("Générer un honeydoc")
    st.caption(
        "Le contenu reste synthétique. Chaque mécanisme garde son propre nom, sa propre source et sa propre garantie."
    )
    canary_official = state.get("connectors", {}).get("canary", {}).get("status") == "configured"
    available_modes = ["local_pixel", "canary_remote", "dual"]
    if canary_official:
        available_modes.append("canary_official")

    with st.form("generate-honeydoc"):
        left, right = st.columns(2)
        campaign = left.text_input("Campagne", "Revue finance et opérations")
        theme = right.text_input("Thème du document", "Prévisions consolidées T4 2026")
        objective = st.text_area(
            "Objectif autorisé",
            "Détecter un accès non prévu à un document synthétique de laboratoire",
            height=80,
        )
        left, middle, right = st.columns(3)
        department = left.text_input("Département", "Direction financière")
        audience = middle.text_input("Destinataires", "Comité de pilotage")
        sensitivity = right.selectbox("Diffusion", ["Restreinte", "Interne", "Confidentielle"])
        sensor_mode = st.selectbox(
            "Mécanisme de détection",
            available_modes,
            format_func=lambda value: MODE_LABELS[value],
        )
        canary_url = ""
        if sensor_mode in {"canary_remote", "dual"}:
            canary_url = st.text_input(
                "URL HTTP du Canarytoken distant",
                placeholder="https://…",
                help="JANUS l'insère telle quelle et ne la renomme jamais pixel local.",
            )
        submitted = st.form_submit_button(
            "Générer le honeydoc", type="primary", use_container_width=True
        )

    if submitted:
        with st.spinner("Génération et validation du DOCX…"):
            result, error = api_post(
                "/api/artifacts",
                {
                    "campaign": campaign,
                    "objective": objective,
                    "theme": theme,
                    "department": department,
                    "audience": audience,
                    "sensitivity": sensitivity,
                    "sensor_mode": sensor_mode,
                    "canary_url": canary_url or None,
                },
            )
        if error:
            st.error(error)
        else:
            artifact = result["artifact"]
            file_data, download_error = api_get(artifact["download_url"], raw=True)
            st.session_state["last_generated"] = artifact
            st.session_state["last_file"] = file_data
            st.success(
                f"{artifact['filename']} est prêt — SHA-256 {artifact['sha256'][:16]}…"
            )
            if download_error:
                st.warning(download_error)

    artifact = st.session_state.get("last_generated")
    file_data = st.session_state.get("last_file")
    if artifact and file_data:
        st.download_button(
            "Télécharger le DOCX",
            data=file_data,
            file_name=artifact["filename"],
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            type="primary",
            use_container_width=True,
        )
        st.caption(
            f"Mode : {MODE_LABELS.get(artifact['sensor_mode'], artifact['sensor_mode'])} · "
            f"Taille : {format_bytes(artifact.get('size_bytes'))} · Contenu : {artifact.get('content_mode')}"
        )


def page_artifacts(state: dict[str, Any]) -> None:
    st.subheader("Artefacts")
    artifacts = state.get("artifacts", [])
    if not artifacts:
        st.info("Aucun artefact enregistré.")
        return
    for artifact in artifacts:
        label = f"{artifact.get('title')} · {MODE_LABELS.get(artifact.get('sensor_mode'), artifact.get('sensor_mode'))}"
        with st.expander(label):
            left, right = st.columns([2, 1])
            left.markdown(
                f"**Fichier :** `{artifact.get('filename')}`  \n"
                f"**SHA-256 :** `{artifact.get('sha256')}`  \n"
                f"**Contenu :** `{artifact.get('content_mode')}`"
            )
            right.metric("Événements", artifact.get("event_count", 0))
            download, error = api_get(f"/api/artifacts/{artifact['id']}/download", raw=True)
            buttons = st.columns(3)
            if not error:
                buttons[0].download_button(
                    "Télécharger",
                    data=download,
                    file_name=artifact["filename"],
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    key=f"download-{artifact['id']}",
                )
            if artifact.get("has_local_pixel") and buttons[1].button(
                "Test pixel contrôlé", key=f"pixel-{artifact['id']}"
            ):
                _, pixel_error = api_post(f"/api/artifacts/{artifact['id']}/pixel-test")
                if pixel_error:
                    st.warning(pixel_error)
                else:
                    st.success("Contact pixel enregistré comme test contrôlé.")
                    st.rerun()
            if buttons[2].button("Test 4663 contrôlé", key=f"demo-{artifact['id']}"):
                _, demo_error = api_post(f"/api/events/demo/{artifact['id']}")
                if demo_error:
                    st.error(demo_error)
                else:
                    st.success("Fixture 4663 enregistrée comme test contrôlé.")
                    st.rerun()


def page_evidence(state: dict[str, Any]) -> None:
    st.subheader("Timeline de preuves")
    events = state.get("events", [])
    if not events:
        st.info("Aucune preuve reçue. La génération elle-même apparaîtra ici après le premier DOCX.")
        return
    rows = [
        {
            "Reçu": fmt_time(event.get("received_at")),
            "Source": event.get("source"),
            "Type": event.get("kind"),
            "Classe": event.get("category"),
            "Force": event.get("strength"),
            "Transport": event.get("transport_trust"),
            "Artefact": event.get("artifact_title") or "—",
            "Résumé": event.get("summary"),
        }
        for event in events
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True, height=420)
    selected = st.selectbox(
        "Inspecter l'événement brut",
        events,
        format_func=lambda event: (
            f"{fmt_time(event.get('received_at'))} · {event.get('source')} · {event.get('kind')}"
        ),
    )
    raw, error = api_get(f"/api/raw/{selected['raw_event_id']}")
    if error:
        st.warning(error)
    else:
        left, right = st.columns(2)
        left.code(raw.get("payload_sha256", ""), language=None)
        right.caption("Empreinte SHA-256 calculée à la réception, avant normalisation.")
        st.json(raw.get("payload"), expanded=False)


def page_wazuh(state: dict[str, Any]) -> None:
    st.subheader("Wazuh et télémétrie")
    connector = state.get("connectors", {}).get("wazuh", {})
    connector_card("État du connecteur Wazuh", connector)
    st.markdown(
        "Les événements inconnus sont conservés avec `normalization_pending`; ils ne sont jamais jetés pour embellir la démonstration."
    )
    artifacts = state.get("artifacts", [])
    if artifacts:
        artifact = st.selectbox(
            "Artefact de laboratoire",
            artifacts,
            format_func=lambda item: item.get("title") or item.get("filename"),
        )
        if st.button("Créer un 4663 contrôlé", type="primary"):
            _, error = api_post(f"/api/events/demo/{artifact['id']}")
            if error:
                st.error(error)
            else:
                st.success("Le test est étiqueté controlled, jamais présenté comme un Wazuh réel.")
                st.rerun()

    st.markdown("### Import manuel d'un JSON Wazuh réel")
    uploaded = st.file_uploader("Fichier JSON", type=["json"])
    pasted = st.text_area("Ou coller un événement", height=160, placeholder='{ "timestamp": "…" }')
    if st.button("Ingérer l'événement Wazuh"):
        if not WAZUH_SECRET:
            st.error("Configurez WAZUH_INGEST_SECRET dans .env avant l'ingestion réelle.")
        else:
            try:
                payload = json.loads(uploaded.getvalue() if uploaded else pasted)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as error:
                st.error(f"JSON invalide : {error}")
            else:
                _, error = api_post(
                    "/api/events/wazuh",
                    payload,
                    headers={"X-JANUS-Wazuh-Secret": WAZUH_SECRET},
                )
                if error:
                    st.error(error)
                else:
                    st.success("Événement brut conservé puis normalisé.")
                    st.rerun()


def page_contract(state: dict[str, Any]) -> None:
    st.subheader("Contrat de vérité")
    st.markdown(
        """
        **Les mécanismes ne sont pas interchangeables.**

        - **Pixel JANUS** : contact HTTP vu par cette instance. Il ne prouve pas à lui seul une ouverture humaine.
        - **Canary distant** : événement déclaré par le fournisseur. Il devient vérifié seulement par webhook authentifié ou historique officiel.
        - **Wazuh 4663** : accès fichier directement observé sur un endpoint instrumenté, mais candidat tant qu'un processus n'est pas corrélé.
        - **4663 + 4688/Sysmon 1** : corroboration seulement si l'hôte et le Logon ID sont identiques dans une fenêtre de cinq secondes.
        - **Test contrôlé** : toujours affiché comme `controlled`; jamais compté comme une attaque réelle.
        """
    )
    st.markdown("### Configuration visible, secrets masqués")
    health, error = api_get("/api/health")
    if error:
        st.error(error)
    else:
        st.json(health)


def inject_style() -> None:
    st.markdown(
        """
        <style>
        :root { --pine:#143f3b; --teal:#0e7067; --lime:#d8f1a9; --ivory:#f6f2e8; --ink:#18302e; }
        .stApp { background: linear-gradient(135deg,#fbfaf5 0%,#f3f0e6 100%); color:var(--ink); }
        [data-testid="stSidebar"] { background:#123b38; }
        [data-testid="stSidebar"] * { color:#f7f3e9 !important; }
        [data-testid="stMetric"] { background:rgba(255,255,255,.78); border:1px solid #d8ddd5; border-radius:16px; padding:16px; box-shadow:0 8px 24px rgba(20,63,59,.06); }
        .hero { display:flex; justify-content:space-between; align-items:center; color:#f8f5ea; background:linear-gradient(130deg,#123f3b,#0e7067); border-radius:24px; padding:28px 34px; margin:2px 0 26px; overflow:hidden; }
        .hero h1 { color:#fff; font:700 3.1rem/1 Georgia,serif; letter-spacing:.02em; margin:.15rem 0; }
        .hero p { color:#e5f0df; margin:0; font-size:1.05rem; }
        .eyebrow { font-size:.7rem; font-weight:800; letter-spacing:.16em; opacity:.82; }
        .hero-mark { width:128px; height:128px; border:1px solid rgba(216,241,169,.55); border-radius:50%; display:grid; place-items:center; position:relative; }
        .hero-mark:before,.hero-mark:after { content:""; position:absolute; border:1px solid rgba(216,241,169,.35); border-radius:50%; inset:16px; }
        .hero-mark:after { inset:34px; background:var(--lime); box-shadow:0 0 0 8px rgba(216,241,169,.14); }
        .connector-card { min-height:160px; background:rgba(255,255,255,.82); border:1px solid #d9ded7; border-radius:18px; padding:18px; }
        .connector-card.ok { border-top:4px solid var(--teal); }
        .connector-card.manual { border-top:4px solid #c3a85d; }
        .connector-card h4 { color:var(--pine); margin:.4rem 0; }
        .connector-card p { color:#54625f; font-size:.88rem; line-height:1.45; }
        .stButton>button[kind="primary"], .stFormSubmitButton>button[kind="primary"] { background:var(--teal); border-color:var(--teal); }
        code { word-break:break-all; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="JANUS Evidence Hub", page_icon="◉", layout="wide")
    inject_style()
    header()
    st.sidebar.markdown("## JANUS")
    page = st.sidebar.radio(
        "Navigation",
        ["Vue d'ensemble", "Générer", "Artefacts", "Preuves", "Wazuh", "Contrat de vérité"],
    )
    if st.sidebar.button("Actualiser", use_container_width=True):
        st.rerun()
    st.sidebar.caption(f"API locale · {API_URL}")

    state = refresh_state()
    if page == "Vue d'ensemble":
        page_overview(state)
    elif page == "Générer":
        page_generate(state)
    elif page == "Artefacts":
        page_artifacts(state)
    elif page == "Preuves":
        page_evidence(state)
    elif page == "Wazuh":
        page_wazuh(state)
    else:
        page_contract(state)


if __name__ == "__main__":
    main()
