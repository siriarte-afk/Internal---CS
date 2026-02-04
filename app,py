import os
import sqlite3
import hashlib
import hmac
import base64 
from pathlib import Path

import streamlit as st
import pandas as pd

APP_TITLE = "Property Library"
DB_PATH = Path("data/app.db")

ALLOWED_TYPES = ["Apartment", "House", "Studio", "Office", "Land"]
ALLOWED_STATUSES = ["Active", "Reserved", "Sold", "Archived"]


def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        property_code TEXT NOT NULL,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        dimension REAL NOT NULL,
        type TEXT NOT NULL,
        estimated_value REAL NOT NULL,
        age INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(user_id, property_code)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS library (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        property_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'Active',
        added_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(property_id) REFERENCES properties(id),
        UNIQUE(user_id, property_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        property_id INTEGER NOT NULL,
        stars INTEGER NOT NULL,
        review TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(property_id) REFERENCES properties(id),
        UNIQUE(user_id, property_id),
        CHECK(stars >= 1 AND stars <= 5)
    )
    """)

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return base64.b64encode(salt + dk).decode("utf-8")

def verify_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored.encode("utf-8"))
    salt = raw[:16]
    dk = raw[16:]
    test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return hmac.compare_digest(test, dk)


def create_user(name, email, password):
    conn = get_conn()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    cur.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        (name.strip(), email.strip().lower(), pw_hash)
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id

def authenticate(email, password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password_hash FROM users WHERE email = ?", (email.strip().lower(),))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


def validate_property(code, name, location, dimension, ptype, value, age):
    if not code or len(code.strip()) < 3:
        return "Property code must be at least 3 characters."
    if not name.strip():
        return "Name is required."
    if not location.strip():
        return "Location is required."
    if dimension <= 0:
        return "Dimension (m²) must be > 0."
    if ptype not in ALLOWED_TYPES:
        return "Invalid property type."
    if value <= 0:
        return "Estimated value must be > 0."
    if age < 0:
        return "Age must be ≥ 0."
    return None


def add_property(user_id, code, name, location, dimension, ptype, value, age):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO properties (user_id, property_code, name, location, dimension, type, estimated_value, age)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, code.strip(), name.strip(), location.strip(),
          float(dimension), ptype, float(value), int(age)))
    prop_id = cur.lastrowid

    cur.execute("""
        INSERT OR IGNORE INTO library (user_id, property_id, status)
        VALUES (?, ?, ?)
    """, (user_id, prop_id, "Active"))

    conn.commit()
    conn.close()
    return prop_id

def update_property(user_id, prop_id, code, name, location, dimension, ptype, value, age):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE properties
        SET property_code=?, name=?, location=?, dimension=?, type=?, estimated_value=?, age=?
        WHERE id=? AND user_id=?
    """, (code.strip(), name.strip(), location.strip(),
          float(dimension), ptype, float(value), int(age), int(prop_id), int(user_id)))
    conn.commit()
    conn.close()

def list_properties(user_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM properties WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def list_library_filtered(user_id, status_list, type_list, query, min_price, max_price, min_m2, max_m2, location_exact):
    conn = get_conn()
    cur = conn.cursor()

    sql = """
    SELECT p.id, p.property_code, p.name, p.location, p.dimension, p.type, p.estimated_value, p.age,
           l.status, p.created_at
    FROM library l
    JOIN properties p ON p.id = l.property_id
    WHERE l.user_id = ?
    """
    params = [user_id]

    if status_list:
        sql += " AND l.status IN ({})".format(",".join(["?"] * len(status_list)))
        params.extend(status_list)

    if type_list:
        sql += " AND p.type IN ({})".format(",".join(["?"] * len(type_list)))
        params.extend(type_list)

    if location_exact and location_exact != "All":
        sql += " AND p.location = ?"
        params.append(location_exact)

    sql += " AND p.estimated_value BETWEEN ? AND ?"
    params.extend([min_price, max_price])

    sql += " AND p.dimension BETWEEN ? AND ?"
    params.extend([min_m2, max_m2])

    if query and query.strip():
        like = f"%{query.strip()}%"
        sql += " AND (p.name LIKE ? OR p.location LIKE ? OR p.property_code LIKE ?)"
        params.extend([like, like, like])

    sql += " ORDER BY p.created_at DESC"

    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def set_status(user_id, property_id, status):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE library SET status=?
        WHERE user_id=? AND property_id=?
    """, (status, int(user_id), int(property_id)))
    conn.commit()
    conn.close()

def upsert_rating(user_id, property_id, stars, review):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ratings (user_id, property_id, stars, review)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id, property_id)
        DO UPDATE SET stars=excluded.stars, review=excluded.review, created_at=datetime('now')
    """, (int(user_id), int(property_id), int(stars), review.strip()))
    conn.commit()
    conn.close()

def get_rating(user_id, property_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT stars, review, created_at
        FROM ratings
        WHERE user_id=? AND property_id=?
    """, (int(user_id), int(property_id)))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def portfolio_stats(user_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            COUNT(*) AS total_properties,
            COALESCE(SUM(estimated_value), 0) AS total_value,
            COALESCE(AVG(dimension), 0) AS avg_size,
            COALESCE(AVG(estimated_value), 0) AS avg_value
        FROM properties
        WHERE user_id=?
    """, (int(user_id),))
    base = dict(cur.fetchone())

    cur.execute("""
        SELECT COALESCE(AVG(estimated_value / NULLIF(dimension, 0)), 0) AS avg_ppm2
        FROM properties
        WHERE user_id=?
    """, (int(user_id),))
    ppm2 = dict(cur.fetchone())

    cur.execute("""
        SELECT status, COUNT(*) AS count
        FROM library
        WHERE user_id=?
        GROUP BY status
        ORDER BY count DESC
    """, (int(user_id),))
    status_rows = [dict(r) for r in cur.fetchall()]

    conn.close()
    return {**base, "avg_price_per_m2": ppm2["avg_ppm2"], "by_status": status_rows}


st.set_page_config(page_title=APP_TITLE, layout="wide")
init_db()

if "user" not in st.session_state:
    st.session_state["user"] = None

st.title(APP_TITLE)
st.sidebar.header("Account")

if st.session_state["user"] is None:
    mode = st.sidebar.radio("Mode", ["Login", "Create account"])

    if mode == "Login":
        email = st.sidebar.text_input("Email")
        password = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Login"):
            u = authenticate(email, password)
            if u:
                st.session_state["user"] = u
                st.rerun()
            else:
                st.sidebar.error("Invalid email or password.")

    else:
        name = st.sidebar.text_input("Name")
        email = st.sidebar.text_input("Email")
        password = st.sidebar.text_input("Password", type="password")
        confirm = st.sidebar.text_input("Confirm password", type="password")
        if st.sidebar.button("Create"):
            if not name.strip():
                st.sidebar.error("Name is required.")
            elif password != confirm or len(password) < 8:
                st.sidebar.error("Passwords must match and be at least 8 characters.")
            else:
                try:
                    create_user(name, email, password)
                    st.sidebar.success("Account created. Now log in.")
                except Exception:
                    st.sidebar.error("Email already exists.")

    st.info("Log in to access your portfolio.")
    st.stop()

st.sidebar.success(f"Logged in as {st.session_state['user']['name']}")
if st.sidebar.button("Logout"):
    st.session_state["user"] = None
    st.rerun()

user_id = st.session_state["user"]["id"]
page = st.sidebar.radio("Navigation", ["Library", "Add / Edit", "Statistics", "Ratings"])


if page == "Library":
    st.subheader("Library")

    props = list_properties(user_id)
    locations = sorted({p["location"] for p in props}) if props else []
    location_pick = st.selectbox("Location", ["All"] + locations)

    c1, c2, c3 = st.columns(3)
    with c1:
        query = st.text_input("Search (code/name/location)")
    with c2:
        status_filter = st.multiselect("Status", ALLOWED_STATUSES, default=["Active"])
    with c3:
        type_filter = st.multiselect("Type", ALLOWED_TYPES, default=ALLOWED_TYPES)

    min_price, max_price = st.slider("Estimated value range", 0, 5_000_000, (0, 5_000_000), step=50_000)
    min_m2, max_m2 = st.slider("Size range (m²)", 0, 2000, (0, 2000), step=5)

    rows = list_library_filtered(
        user_id=user_id,
        status_list=status_filter,
        type_list=type_filter,
        query=query,
        min_price=min_price,
        max_price=max_price,
        min_m2=min_m2,
        max_m2=max_m2,
        location_exact=location_pick
    )

    if not rows:
        st.warning("No matching properties found.")
        st.stop()

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)

    st.download_button(
        "Export current view (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="properties.csv",
        mime="text/csv"
    )

    st.divider()
    st.subheader("Update status")
    prop_id = st.selectbox("Select property ID", df["id"].tolist())
    new_status = st.selectbox("New status", ALLOWED_STATUSES)
    if st.button("Update status"):
        set_status(user_id, prop_id, new_status)
        st.success("Status updated.")
        st.rerun()


elif page == "Add / Edit":
    st.subheader("Add property")

    with st.form("add_form"):
        code = st.text_input("Property code (unique)", help="Example: PRD-001")
        name = st.text_input("Name")
        location = st.text_input("Location / Neighborhood")
        dimension = st.number_input("Size (m²)", min_value=0.0, step=1.0)
        ptype = st.selectbox("Type", ALLOWED_TYPES)
        value = st.number_input("Estimated value", min_value=0.0, step=10_000.0)
        age = st.number_input("Age (years)", min_value=0, step=1)
        add_btn = st.form_submit_button("Add property")

    if add_btn:
        err = validate_property(code, name, location, dimension, ptype, value, age)
        if err:
            st.error(err)
        else:
            try:
                pid = add_property(user_id, code, name, location, dimension, ptype, value, age)
                st.success(f"Added property (ID {pid}).")
            except Exception:
                st.error("Duplicate property code detected. Use a different code.")

    st.divider()
    st.subheader("Edit property")

    props = list_properties(user_id)
    if not props:
        st.info("No properties to edit yet.")
        st.stop()

    pick_map = {f"{p['property_code']} — {p['name']} (ID {p['id']})": p["id"] for p in props}
    pick_label = st.selectbox("Choose property", list(pick_map.keys()))
    prop_id = pick_map[pick_label]
    current = next(p for p in props if p["id"] == prop_id)

    with st.form("edit_form"):
        e_code = st.text_input("Property code", value=current["property_code"])
        e_name = st.text_input("Name", value=current["name"])
        e_loc = st.text_input("Location", value=current["location"])
        e_dim = st.number_input("Size (m²)", min_value=0.0, step=1.0, value=float(current["dimension"]))
        e_type = st.selectbox("Type", ALLOWED_TYPES, index=ALLOWED_TYPES.index(current["type"]))
        e_val = st.number_input("Estimated value", min_value=0.0, step=10_000.0, value=float(current["estimated_value"]))
        e_age = st.number_input("Age (years)", min_value=0, step=1, value=int(current["age"]))
        save_btn = st.form_submit_button("Save changes")

    if save_btn:
        err = validate_property(e_code, e_name, e_loc, e_dim, e_type, e_val, e_age)
        if err:
            st.error(err)
        else:
            try:
                update_property(user_id, prop_id, e_code, e_name, e_loc, e_dim, e_type, e_val, e_age)
                st.success("Updated.")
                st.rerun()
            except Exception:
                st.error("Update failed (possibly duplicate property code).")


elif page == "Statistics":
    st.subheader("Portfolio statistics")

    stats = portfolio_stats(user_id)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total properties", int(stats["total_properties"]))
    c2.metric("Total value", f"{stats['total_value']:.0f}")
    c3.metric("Avg size (m²)", f"{stats['avg_size']:.1f}")
    c4.metric("Avg price per m²", f"{stats['avg_price_per_m2']:.1f}")

    st.write("Counts by status:")
    if stats["by_status"]:
        st.dataframe(pd.DataFrame(stats["by_status"]), use_container_width=True)
    else:
        st.info("No status data yet.")


else:
    st.subheader("Ratings")

    props = list_properties(user_id)
    if not props:
        st.info("Add a property first.")
        st.stop()

    pick_map = {f"{p['property_code']} — {p['name']} (ID {p['id']})": p["id"] for p in props}
    pick_label = st.selectbox("Choose property", list(pick_map.keys()))
    prop_id = pick_map[pick_label]

    existing = get_rating(user_id, prop_id)
    default_stars = existing["stars"] if existing else 3
    default_review = existing["review"] if existing else ""

    stars = st.slider("Stars (1–5)", 1, 5, int(default_stars))
    review = st.text_area("Review / Notes", value=default_review)

    if st.button("Save rating"):
        upsert_rating(user_id, prop_id, stars, review)
        st.success("Saved.")
        st.rerun()
 
