"""
dashboard/auth.py
=================
Password gate for the dashboard.

Configure with IDS_DASH_PASSWORD_SHA256 (preferred; hex SHA-256 of the password) or IDS_DASH_PASSWORD.
With neither set the gate is open and the sidebar says so. Wrong guesses are slowed in-session; for
internet-facing use put the dashboard behind a reverse proxy with SSO (see docs/SECURITY.md).
"""

from __future__ import annotations

import hashlib
import hmac
import time

import streamlit as st

from config import DASH_PASSWORD, DASH_PASSWORD_SHA256


def auth_enabled() -> bool:
    return bool(DASH_PASSWORD or DASH_PASSWORD_SHA256)


def check_password(candidate: str) -> bool:
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    if DASH_PASSWORD_SHA256:
        return hmac.compare_digest(digest, DASH_PASSWORD_SHA256.strip().lower())
    return hmac.compare_digest(digest, hashlib.sha256(DASH_PASSWORD.encode()).hexdigest())


def require_login() -> None:
    """Render a login form and stop the script until the user is authenticated."""
    if not auth_enabled() or st.session_state.get("authed"):
        return
    st.title("Network IDS")
    st.caption("Sign in to continue.")
    with st.form("login", clear_on_submit=True):
        pw = st.text_input("Password", type="password")
        go = st.form_submit_button("Sign in", type="primary")
    if go:
        fails = st.session_state.get("login_fails", 0)
        time.sleep(min(fails, 5))
        if check_password(pw):
            st.session_state["authed"] = True
            st.session_state["login_fails"] = 0
            st.rerun()
        st.session_state["login_fails"] = fails + 1
        st.error("Wrong password. Try again.")
    st.stop()


def sidebar_status() -> None:
    if not auth_enabled():
        st.caption(":material/lock_open: Login is off. Set IDS_DASH_PASSWORD_SHA256 before sharing this dashboard.")
    elif st.sidebar.button("Sign out", icon=":material/logout:"):
        st.session_state.clear()
        st.rerun()
