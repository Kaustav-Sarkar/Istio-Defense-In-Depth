import streamlit as st
import pandas as pd
import requests
import os

# Set page configuration
st.set_page_config(
    page_title="HR Employee Directory",
    page_icon="👥",
    layout="wide",
    initial_sidebar_state="expanded"
)

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://app.localtest.me")

def get_cookies():
    # Use st.context.cookies (Streamlit >= 1.37)
    if hasattr(st, "context") and hasattr(st.context, "cookies"):
        return st.context.cookies
    return {}

def get_session():
    cookies = get_cookies()
    if "zt_session" not in cookies:
        return None
        
    try:
        # Call auth-service via gateway
        response = requests.get(
            f"{GATEWAY_URL}/auth/session",
            cookies={"zt_session": cookies["zt_session"]},
            timeout=2.0,
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        st.sidebar.error(f"Session error: {e}")
    return None

def api_get(path):
    cookies = get_cookies()
    try:
        response = requests.get(
            f"{GATEWAY_URL}{path}",
            cookies={"zt_session": cookies.get("zt_session", "")},
            timeout=5.0,
        )
        return response
    except Exception as e:
        st.error(f"API request failed: {e}")
        return None

def get_profile_employee_id(session):
    return session.get("user_id")

def get_session_display_name(session):
    return session.get("username") or session.get("user_id", "User")

# --- View Implementations ---

def render_employee_summary(emp, pii_error=None, fin_error=None):
    # Employee Details Section
    st.subheader("Employee Details")
    st.info("Notice how Cerbos masking rules apply to the data below based on your role.")
    
    if pii_error == "Forbidden":
        st.warning("You do not have permission to view PII data for this employee.")
    elif pii_error:
        st.error(f"Could not load PII data: {pii_error}")
        
    if fin_error == "Forbidden":
        st.warning("You do not have permission to view financial data for this employee.")
    elif fin_error:
        st.error(f"Could not load financial data: {fin_error}")
    
    with st.container(border=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Name:** {emp.get('first_name', '***')} {emp.get('last_name', '***')}")
            st.markdown(f"**Role:** {emp.get('job_title', '***')}")
            st.markdown(f"**Department:** {emp.get('department', '***')}")
            st.markdown(f"**Email:** {emp.get('work_email', '***')}")
            
        with col2:
            st.markdown(f"**ID:** `{emp.get('id', 'N/A')}`")
            st.markdown(f"**Manager ID:** `{emp.get('manager_id', 'None')}`")
            st.markdown(f"**SSN:** {emp.get('ssn', 'Not Visible')}")
            
            salary_display = "Not Visible"
            if "base_salary" in emp:
                salary_display = f"${emp['base_salary']}"
            elif "salary_band" in emp:
                salary_display = emp["salary_band"]
                
            st.markdown(f"**Salary:** {salary_display}")
        
def render_assets_table(assets, assets_error=None):
    st.subheader("Assigned Hardware Assets")
    if assets_error == "Forbidden":
        st.warning("You do not have permission to view Hardware assets for this employee.")
    elif assets_error:
        st.error(f"Could not load hardware assets: {assets_error}")
    elif assets:
        df_assets = pd.DataFrame(assets)
        st.dataframe(df_assets, use_container_width=True, hide_index=True)
    else:
        st.info("No hardware assets assigned.")

def render_raw_response(data):
    with st.expander("View Raw JSON Response"):
        st.json(data)

def render_access_result(session, path, status_code, data):
    st.subheader("Access Result")
    roles = ", ".join(session.get("roles", []))
    st.write(f"**Principal Roles:** {roles}")
    st.write(f"**Query Path:** `{path}`")
    st.write(f"**Status Code:** `{status_code}`")
    
    emp = data.get("employee", {}) if isinstance(data, dict) else {}
    assets = data.get("assets", []) if isinstance(data, dict) else []
    
    fields_to_check = ["ssn", "date_of_birth", "salary_band", "base_salary"]
    
    present_fields = [f for f in fields_to_check if f in emp]
    masked_fields = [f for f in fields_to_check if f not in emp]
    
    asset_fields = ["serial_number", "mac_address"]
    asset_present = set()
    asset_masked = set()
    
    for asset in assets:
        for f in asset_fields:
            if f in asset and not str(asset[f]).startswith("***"):
                asset_present.add(f)
            else:
                asset_masked.add(f)
                
    st.write(f"**Employee Sensitive Fields Present:** {', '.join(present_fields) if present_fields else 'None'}")
    st.write(f"**Employee Sensitive Fields Masked/Absent:** {', '.join(masked_fields) if masked_fields else 'None'}")
    
    if assets:
        st.write(f"**Asset Sensitive Fields Present:** {', '.join(list(asset_present)) if asset_present else 'None'}")
        st.write(f"**Asset Sensitive Fields Masked/Absent:** {', '.join(list(asset_masked)) if asset_masked else 'None'}")

import uuid

def get_demo_user_id(username):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"istio-security://users/{username}"))

DEMO_USERS = {
    "My Profile (Session User)": None,
    "Alice (Employee)": get_demo_user_id("alice.employee"),
    "Mary (Manager)": get_demo_user_id("mary.manager"),
    "Henry (HR Admin)": get_demo_user_id("henry.hradmin"),
    "Ivan (IT Admin)": get_demo_user_id("ivan.itadmin"),
}

def render_profile_view(session):
    st.title("🔍 Employee Profile Query")
    st.markdown("---")
    
    session_user_id = get_profile_employee_id(session)
    if not session_user_id:
        st.error("No employee ID found in session.")
        return
        
    st.write("Select a target employee to query their profile.")
    
    target_choice = st.selectbox("Target Employee", list(DEMO_USERS.keys()))
    custom_id = ""
    
    if target_choice == "My Profile (Session User)":
        target_id = session_user_id
    else:
        target_id = DEMO_USERS[target_choice]
        
    target_id_input = st.text_input("Or enter custom Employee ID (UUID)", value=target_id)
    
    if st.button("Run Query"):
        query_id = target_id_input or target_id
        path = f"/api/profile/{query_id}"
        
        with st.spinner(f"Loading profile for {query_id}..."):
            response = api_get(path)
            
        if response is None:
            st.error("Failed to execute query.")
            return
            
        status_code = response.status_code
        try:
            data = response.json()
        except:
            data = {"raw_text": response.text}
            
        render_access_result(session, path, status_code, data)
        st.markdown("---")
            
        if status_code == 200:
            emp = data.get("employee", {})
            assets = data.get("assets", [])
            assets_error = data.get("assets_error")
            pii_error = data.get("pii_error")
            fin_error = data.get("fin_error")
            
            render_employee_summary(emp, pii_error, fin_error)
            st.markdown("---")
            render_assets_table(assets, assets_error)
        else:
            st.error(f"Query failed with status {status_code}")
            
        st.markdown("---")
        render_raw_response(data)

def render_holidays_view():
    st.title("📅 Holiday Calendar")
    st.markdown("---")
    st.write("Upcoming company holidays across all regions.")
    
    with st.spinner("Loading holidays..."):
        response = api_get("/api/holidays")
        
    if response is None or response.status_code != 200:
        st.error(f"Failed to load holidays. Status code: {response.status_code if response is not None else 'Unknown'}")
        return
        
    holidays = response.json()
    if not holidays:
        st.info("No holidays found.")
        return
        
    df_holidays = pd.DataFrame(holidays)
    st.dataframe(df_holidays, use_container_width=True, hide_index=True)

def render_offices_view():
    st.title("🏢 Office Locations")
    st.markdown("---")
    st.write("Global office locations and their current status.")
    
    with st.spinner("Loading offices..."):
        response = api_get("/api/offices")
        
    if response is None or response.status_code != 200:
        st.error(f"Failed to load offices. Status code: {response.status_code if response is not None else 'Unknown'}")
        return
        
    offices = response.json()
    if not offices:
        st.info("No offices found.")
        return
        
    df_offices = pd.DataFrame(offices)
    st.dataframe(df_offices, use_container_width=True, hide_index=True)

# --- Main App ---

def main():
    session = get_session()
    
    # Sidebar Navigation
    st.sidebar.title("HR Portal Navigation")
    
    if not session:
        st.sidebar.warning("You are not logged in.")
        st.sidebar.markdown(f"[Login here]({GATEWAY_URL}/auth/login)")
        
        view = st.sidebar.radio("Select a view:", ("Welcome", "Office Locations"))
        
        if view == "Welcome":
            st.title("Welcome to HR Portal")
            st.write("Please log in to access your profile and company resources.")
            
            if os.getenv("SHOW_DEMO_USERS", "").lower() == "true":
                st.info("""
**Demo Credentials:**
- **Alice (Employee):** `alice.employee` / `alice-password`
- **Mary (Manager):** `mary.manager` / `mary-password`
- **Henry (HR Admin):** `henry.hradmin` / `henry-password`
- **Ivan (IT Admin):** `ivan.itadmin` / `ivan-password`
                """)
        elif view == "Office Locations":
            render_offices_view()
        return
        
    st.sidebar.success(f"Logged in as: {get_session_display_name(session)}")
    st.sidebar.write(f"Roles: {', '.join(session.get('roles', []))}")
    
    st.sidebar.markdown(f'<a href="{GATEWAY_URL}/auth/logout" target="_self">Logout</a>', unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    view = st.sidebar.radio(
        "Select a view:",
        ("Profile", "Holiday Calendar", "Office Locations")
    )
    
    # Render selected view
    if view == "Profile":
        render_profile_view(session)
    elif view == "Holiday Calendar":
        render_holidays_view()
    elif view == "Office Locations":
        render_offices_view()

if __name__ == "__main__":
    main()
