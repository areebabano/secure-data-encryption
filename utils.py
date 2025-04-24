import time
import streamlit as st 

def check_lockout():
    if "lockout_time" in st.session_state:
        elapsed = time.time() - st.session_state.lockout_time
        if elapsed < 60:
            return True, 60 - elapsed
        else:
            del st.session_state.lockout_time
            return False, 0
    return False, 0  # <-- ✅ this was missing
