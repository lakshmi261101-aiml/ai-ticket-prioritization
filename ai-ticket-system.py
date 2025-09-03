import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import plotly.express as px
import plotly.graph_objects as go
import datetime
import time
import re
import json
import io

# Page config
st.set_page_config(page_title="AI Ticket Prioritization System", page_icon="🎫", layout="wide")

# CSS Styles
st.markdown("""
<style>
    .main-header { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1rem; border-radius: 10px; color: white; text-align: center; margin-bottom: 2rem; font-size: 1.5rem; font-weight: bold; }
    .status-open { background-color: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .status-in_progress { background-color: #fff3e0; color: #f57c00; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .status-resolved { background-color: #e8f5e8; color: #388e3c; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .status-closed { background-color: #f3e5f5; color: #7b1fa2; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .priority-critical { background-color: #ffebee; color: #d32f2f; padding: 4px 8px; border-radius: 12px; font-weight: bold; font-size: 0.8rem; }
    .priority-high { background-color: #fff3e0; color: #f57c00; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .priority-medium { background-color: #e8f5e8; color: #388e3c; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .priority-low { background-color: #f3e5f5; color: #7b1fa2; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; }
    .import-section { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 15px; margin: 2rem 0; box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3); color: white; }
    .success-msg { background: linear-gradient(135deg, #2ecc71, #27ae60); color: white; padding: 1rem; border-radius: 10px; margin: 1rem 0; }
    .error-msg { background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 1rem; border-radius: 10px; margin: 1rem 0; }
</style>
""", unsafe_allow_html=True)

# Database initialization
@st.cache_resource
def init_database():
    conn = sqlite3.connect('ai_ticket_system.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'support_agent',
        full_name TEXT,
        department TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Tickets table
    cursor.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'medium',
        category TEXT,
        created_by INTEGER,
        assigned_to INTEGER,
        sla_deadline TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id),
        FOREIGN KEY (assigned_to) REFERENCES users (id)
    )''')
    
    # Ticket history table
    cursor.execute('''CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER,
        action TEXT,
        old_value TEXT,
        new_value TEXT,
        changed_by INTEGER,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ticket_id) REFERENCES tickets (id)
    )''')
    
    # Create default users if none exist
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # Admin user
        admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute('''INSERT INTO users (username, email, password_hash, role, full_name, department) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      ('admin', 'admin@company.com', admin_hash, 'admin', 'System Admin', 'IT'))
        
        # Manager user
        manager_hash = hashlib.sha256('manager123'.encode()).hexdigest()
        cursor.execute('''INSERT INTO users (username, email, password_hash, role, full_name, department) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      ('manager', 'manager@company.com', manager_hash, 'manager', 'Support Manager', 'Support'))
        
        # Agent user
        agent_hash = hashlib.sha256('agent123'.encode()).hexdigest()
        cursor.execute('''INSERT INTO users (username, email, password_hash, role, full_name, department) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      ('agent1', 'agent@company.com', agent_hash, 'support_agent', 'John Agent', 'Support'))
        
        # Sample tickets
        sample_tickets = [
            ('Network Outage Building A', 'Complete network failure in Building A affecting all users', 'open', 'critical', 'network', 1, None),
            ('Email Server Slow', 'Email server experiencing performance issues', 'in_progress', 'high', 'email', 2, 3),
            ('Printer Not Working', 'Office printer on 3rd floor not responding', 'resolved', 'medium', 'hardware', 3, 3),
            ('Password Reset Request', 'User unable to access system after password change', 'open', 'low', 'access', 2, None),
            ('VPN Connection Issues', 'Remote users cannot connect to VPN', 'in_progress', 'high', 'network', 1, 3),
            ('Software Installation', 'Need to install new software for marketing team', 'open', 'medium', 'software', 2, None),
            ('Database Performance', 'Database queries running very slowly', 'open', 'critical', 'database', 1, None),
            ('Security Alert', 'Suspicious login attempts detected', 'resolved', 'high', 'security', 1, 3)
        ]
        
        for ticket in sample_tickets:
            # Calculate SLA deadline based on priority
            hours_map = {'critical': 4, 'high': 24, 'medium': 72, 'low': 168}
            sla_deadline = datetime.datetime.now() + datetime.timedelta(hours=hours_map[ticket[3]])
            
            cursor.execute('''INSERT INTO tickets (title, description, status, priority, category, created_by, assigned_to, sla_deadline) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                          (*ticket, sla_deadline.strftime('%Y-%m-%d %H:%M:%S')))
    
    conn.commit()
    return conn

# AI Classification System
class TicketClassifier:
    def __init__(self):
        self.categories = {
            'network': ['network', 'internet', 'wifi', 'connection', 'router', 'switch', 'ethernet', 'vpn', 'bandwidth'],
            'hardware': ['printer', 'computer', 'laptop', 'monitor', 'keyboard', 'mouse', 'device', 'equipment'],
            'software': ['software', 'application', 'program', 'app', 'installation', 'update', 'bug', 'crash'],
            'email': ['email', 'mail', 'outlook', 'smtp', 'attachment', 'inbox'],
            'database': ['database', 'sql', 'query', 'data', 'backup', 'performance'],
            'security': ['security', 'virus', 'malware', 'breach', 'unauthorized', 'hack'],
            'access': ['password', 'login', 'access', 'account', 'permission', 'authentication'],
            'communication': ['phone', 'call', 'meeting', 'conference', 'audio', 'video']
        }
        
        self.priority_keywords = {
            'critical': ['critical', 'urgent', 'emergency', 'down', 'outage', 'failure', 'crash', 'breach'],
            'high': ['high', 'important', 'asap', 'affecting multiple', 'slow', 'performance'],
            'medium': ['medium', 'normal', 'standard'],
            'low': ['low', 'minor', 'request', 'question']
        }
    
    def classify_ticket(self, title, description):
        text = f"{title} {description}".lower()
        
        # Category classification
        category_scores = {}
        for category, keywords in self.categories.items():
            score = sum(1 for keyword in keywords if keyword in text)
            category_scores[category] = score
        
        predicted_category = max(category_scores, key=category_scores.get) if max(category_scores.values()) > 0 else 'general'
        
        # Priority classification
        priority_scores = {}
        for priority, keywords in self.priority_keywords.items():
            score = sum(2 for keyword in keywords if keyword in text)
            priority_scores[priority] = score
        
        if max(priority_scores.values()) > 0:
            predicted_priority = max(priority_scores, key=priority_scores.get)
        else:
            # Default based on category
            if predicted_category in ['network', 'security', 'database']:
                predicted_priority = 'high'
            else:
                predicted_priority = 'medium'
        
        confidence = min(max(category_scores.values()) + max(priority_scores.values()), 10) / 10.0
        
        return predicted_category, predicted_priority, confidence

# Helper functions
def get_db():
    return sqlite3.connect('ai_ticket_system.db', check_same_thread=False)

def authenticate_user(username, password):
    conn = get_db()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username, email, password, full_name, department, role='support_agent'):
    conn = get_db()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    try:
        cursor.execute('''INSERT INTO users (username, email, password_hash, full_name, department, role) 
                         VALUES (?, ?, ?, ?, ?, ?)''', (username, email, password_hash, full_name, department, role))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def get_dashboard_stats():
    conn = get_db()
    
    total_tickets = pd.read_sql_query("SELECT COUNT(*) as count FROM tickets", conn).iloc[0]['count']
    open_tickets = pd.read_sql_query("SELECT COUNT(*) as count FROM tickets WHERE status IN ('open', 'in_progress')", conn).iloc[0]['count']
    critical_tickets = pd.read_sql_query("SELECT COUNT(*) as count FROM tickets WHERE priority = 'critical'", conn).iloc[0]['count']
    overdue_tickets = pd.read_sql_query("SELECT COUNT(*) as count FROM tickets WHERE sla_deadline < datetime('now') AND status NOT IN ('resolved', 'closed')", conn).iloc[0]['count']
    resolved_today = pd.read_sql_query("SELECT COUNT(*) as count FROM tickets WHERE status = 'resolved' AND date(resolved_at) = date('now')", conn).iloc[0]['count']
    
    status_dist = pd.read_sql_query("SELECT status, COUNT(*) as count FROM tickets GROUP BY status", conn)
    priority_dist = pd.read_sql_query("SELECT priority, COUNT(*) as count FROM tickets GROUP BY priority", conn)
    category_dist = pd.read_sql_query("SELECT category, COUNT(*) as count FROM tickets GROUP BY category", conn)
    
    conn.close()
    
    return {
        'total': total_tickets, 'open': open_tickets, 'critical': critical_tickets,
        'overdue': overdue_tickets, 'resolved_today': resolved_today,
        'status_dist': status_dist, 'priority_dist': priority_dist, 'category_dist': category_dist
    }

def get_tickets(user_id=None, role=None, status_filter=None):
    conn = get_db()
    
    query = """SELECT t.*, u1.full_name as created_by_name, u2.full_name as assigned_to_name
               FROM tickets t 
               LEFT JOIN users u1 ON t.created_by = u1.id 
               LEFT JOIN users u2 ON t.assigned_to = u2.id WHERE 1=1"""
    params = []
    
    if role == 'support_agent' and user_id:
        query += " AND (t.assigned_to = ? OR t.created_by = ?)"
        params.extend([user_id, user_id])
    
    if status_filter and status_filter != 'All':
        query += " AND t.status = ?"
        params.append(status_filter)
    
    query += " ORDER BY t.created_at DESC"
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df

def create_ticket(title, description, category, user_id):
    classifier = TicketClassifier()
    predicted_cat, predicted_priority, confidence = classifier.classify_ticket(title, description)
    
    if category == 'Auto-classify':
        category = predicted_cat
    
    # Calculate SLA deadline
    hours_map = {'critical': 4, 'high': 24, 'medium': 72, 'low': 168}
    sla_deadline = datetime.datetime.now() + datetime.timedelta(hours=hours_map[predicted_priority])
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO tickets (title, description, category, priority, created_by, sla_deadline)
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                  (title, description, category, predicted_priority, user_id, sla_deadline.strftime('%Y-%m-%d %H:%M:%S')))
    
    ticket_id = cursor.lastrowid
    
    # Log creation
    cursor.execute('''INSERT INTO ticket_history (ticket_id, action, new_value, changed_by)
                     VALUES (?, ?, ?, ?)''', (ticket_id, 'created', f'{category}/{predicted_priority}', user_id))
    
    conn.commit()
    conn.close()
    
    return ticket_id, predicted_priority, confidence

def update_ticket_status(ticket_id, new_status, user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get current status
    cursor.execute('SELECT status FROM tickets WHERE id = ?', (ticket_id,))
    old_status = cursor.fetchone()[0]
    
    # Update ticket
    if new_status == 'resolved':
        cursor.execute('UPDATE tickets SET status = ?, resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_status, ticket_id))
    else:
        cursor.execute('UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_status, ticket_id))
    
    # Log change
    cursor.execute('INSERT INTO ticket_history (ticket_id, action, old_value, new_value, changed_by) VALUES (?, ?, ?, ?, ?)',
                  (ticket_id, 'status_change', old_status, new_status, user_id))
    
    conn.commit()
    conn.close()

def assign_ticket(ticket_id, assigned_to, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE tickets SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (assigned_to, ticket_id))
    cursor.execute('INSERT INTO ticket_history (ticket_id, action, new_value, changed_by) VALUES (?, ?, ?, ?)',
                  (ticket_id, 'assigned', str(assigned_to), user_id))
    conn.commit()
    conn.close()

def export_tickets_csv():
    conn = get_db()
    df = pd.read_sql_query("""SELECT t.id, t.title, t.description, t.status, t.priority, t.category, 
                             t.created_at, u1.full_name as created_by, u2.full_name as assigned_to
                             FROM tickets t 
                             LEFT JOIN users u1 ON t.created_by = u1.id 
                             LEFT JOIN users u2 ON t.assigned_to = u2.id""", conn)
    conn.close()
    return df.to_csv(index=False)

# FIXED: CSV Import Functions
def validate_csv_data(df):
    """Validate CSV data before import"""
    errors = []
    
    # Check required columns
    required_cols = ['title', 'description']
    for col in required_cols:
        if col not in df.columns:
            errors.append(f"Missing required column: {col}")
    
    # Check for empty required fields
    for idx, row in df.iterrows():
        if pd.isna(row.get('title', '')) or str(row.get('title', '')).strip() == '':
            errors.append(f"Row {idx + 2}: Title is required")
        if pd.isna(row.get('description', '')) or str(row.get('description', '')).strip() == '':
            errors.append(f"Row {idx + 2}: Description is required")
    
    return errors

def get_user_by_username(username):
    """Get user ID by username for assignment"""
    if not username or pd.isna(username) or str(username).strip() == '':
        return None
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (str(username).strip(),))
    result = cursor.fetchone()
    conn.close()
    
    return result[0] if result else None

def process_csv_import(file_content, user_id):
    """Process CSV file content and import tickets - FIXED VERSION"""
    try:
        # Read CSV from string content
        df = pd.read_csv(io.StringIO(file_content))
        
        st.write(f"📊 **CSV loaded with {len(df)} rows and {len(df.columns)} columns**")
        st.write(f"**Columns found:** {', '.join(df.columns.tolist())}")
        
        # Validate data
        errors = validate_csv_data(df)
        if errors:
            st.error("❌ **Validation Errors:**")
            for error in errors:
                st.write(f"• {error}")
            return False, errors, 0
        
        # Initialize classifier
        classifier = TicketClassifier()
        
        # Process each row
        imported_count = 0
        import_errors = []
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Create progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for idx, row in df.iterrows():
            try:
                # Update progress
                progress = (idx + 1) / len(df)
                progress_bar.progress(progress)
                status_text.text(f"Processing row {idx + 1}/{len(df)}: {row['title'][:50]}...")
                
                # Clean and validate data
                title = str(row['title']).strip()
                description = str(row['description']).strip()
                
                if not title or not description:
                    import_errors.append(f"Row {idx + 2}: Missing title or description")
                    continue
                
                # Get or predict category
                category = str(row.get('category', '')).strip() if 'category' in df.columns else ''
                if not category or category.lower() in ['', 'nan', 'none']:
                    category, _, _ = classifier.classify_ticket(title, description)
                
                # Get or predict priority
                priority = str(row.get('priority', '')).strip().lower() if 'priority' in df.columns else ''
                if priority not in ['critical', 'high', 'medium', 'low'] or priority in ['', 'nan', 'none']:
                    _, priority, _ = classifier.classify_ticket(title, description)
                
                # Handle assignment
                assigned_to = None
                if 'assigned_to' in df.columns and pd.notna(row['assigned_to']):
                    assigned_to_username = str(row['assigned_to']).strip()
                    if assigned_to_username and assigned_to_username.lower() not in ['', 'nan', 'none']:
                        assigned_to = get_user_by_username(assigned_to_username)
                        if not assigned_to:
                            import_errors.append(f"Row {idx + 2}: User '{assigned_to_username}' not found")
                
                # Calculate SLA
                hours_map = {'critical': 4, 'high': 24, 'medium': 72, 'low': 168}
                sla_deadline = datetime.datetime.now() + datetime.timedelta(hours=hours_map[priority])
                
                # Insert ticket
                cursor.execute('''INSERT INTO tickets (title, description, category, priority, created_by, assigned_to, sla_deadline)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                              (title, description, category, priority, user_id, assigned_to, sla_deadline.strftime('%Y-%m-%d %H:%M:%S')))
                
                # Log creation
                ticket_id = cursor.lastrowid
                cursor.execute('''INSERT INTO ticket_history (ticket_id, action, new_value, changed_by)
                                 VALUES (?, ?, ?, ?)''', (ticket_id, 'created', f'{category}/{priority}', user_id))
                
                imported_count += 1
                
            except Exception as e:
                import_errors.append(f"Row {idx + 2}: {str(e)}")
                st.write(f"❌ Error on row {idx + 2}: {str(e)}")
        
        # Finalize
        progress_bar.progress(1.0)
        status_text.text(f"✅ Processing complete!")
        
        conn.commit()
        conn.close()
        
        return True, import_errors, imported_count
        
    except Exception as e:
        st.error(f"❌ **File processing error:** {str(e)}")
        return False, [f"File processing error: {str(e)}"], 0

def generate_sample_csv():
    """Generate sample CSV content for download"""
    sample_data = """title,description,category,priority,assigned_to
Network Outage Building C,Complete network failure in Building C,network,critical,agent1
Printer Issues Office 302,Color printer not responding to print jobs,hardware,medium,agent1
Email Server Performance,Slow email delivery and timeouts,email,high,agent1
Password Reset Request,User John Smith needs password reset,access,low,agent1
Software Installation Request,Need Microsoft Office on new computer,software,medium,agent1
Database Query Slow,Customer portal loading very slowly,database,high,
WiFi Problems Conference Room,Intermittent connectivity during meetings,network,medium,agent1
Security Alert Detected,Suspicious login attempts from unknown IP,security,critical,
Keyboard Not Working,Executive assistant keyboard keys not responding,hardware,low,
VPN Connection Failed,Remote workers cannot connect to company VPN,network,high,agent1"""
    
    return sample_data

# Initialize components
conn = init_database()
classifier = TicketClassifier()

# Session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'page' not in st.session_state:
    st.session_state.page = 'login'

# Authentication page
def auth_page():
    st.markdown('<div class="main-header">🎫 AI Ticket Prioritization System</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        tab1, tab2 = st.tabs(["Login", "Sign Up"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                login_btn = st.form_submit_button("Login", use_container_width=True)
                
                if login_btn and username and password:
                    user = authenticate_user(username, password)
                    if user:
                        st.session_state.authenticated = True
                        st.session_state.user = user
                        st.success(f"Welcome, {user[5]}!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
            
            st.info("**Demo Accounts:**\n- Admin: admin/admin123\n- Manager: manager/manager123\n- Agent: agent1/agent123")
        
        with tab2:
            with st.form("signup_form"):
                new_username = st.text_input("Username*")
                new_email = st.text_input("Email*")
                new_name = st.text_input("Full Name*")
                new_dept = st.text_input("Department")
                new_password = st.text_input("Password*", type="password")
                role = st.selectbox("Role", ["support_agent", "manager"])
                signup_btn = st.form_submit_button("Create Account", use_container_width=True)
                
                if signup_btn:
                    if all([new_username, new_email, new_name, new_password]):
                        if create_user(new_username, new_email, new_password, new_name, new_dept, role):
                            st.success("Account created! Please login.")
                        else:
                            st.error("Username/email already exists")
                    else:
                        st.error("Please fill all required fields")

# Dashboard page
def dashboard_page():
    st.markdown('<div class="main-header">📊 Support Dashboard</div>', unsafe_allow_html=True)
    
    stats = get_dashboard_stats()
    
    # Key metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Tickets", stats['total'])
    col2.metric("Open Tickets", stats['open'])
    col3.metric("Critical Priority", stats['critical'])
    col4.metric("⚠️ Overdue", stats['overdue'], delta_color="inverse")
    col5.metric("Resolved Today", stats['resolved_today'])
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Status Distribution")
        if not stats['status_dist'].empty:
            fig = px.pie(stats['status_dist'], values='count', names='status',
                        color_discrete_map={'open': '#3498db', 'in_progress': '#f39c12', 'resolved': '#2ecc71', 'closed': '#95a5a6'})
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Priority Breakdown")
        if not stats['priority_dist'].empty:
            fig = px.bar(stats['priority_dist'], x='priority', y='count',
                        color='priority', color_discrete_map={'critical': '#e74c3c', 'high': '#f39c12', 'medium': '#f1c40f', 'low': '#9b59b6'})
            st.plotly_chart(fig, use_container_width=True)
    
    # Category distribution
    if not stats['category_dist'].empty:
        st.subheader("📂 Category Distribution")
        fig = px.bar(stats['category_dist'], x='category', y='count', color='count', color_continuous_scale='viridis')
        st.plotly_chart(fig, use_container_width=True)

# Enhanced Tickets page with FIXED CSV import
def tickets_page():
    st.markdown('<div class="main-header">🎫 Ticket Management</div>', unsafe_allow_html=True)
    
    # Enhanced tabs with CSV import
    if st.session_state.user[4] in ['admin', 'manager']:
        tab1, tab2, tab3 = st.tabs(["📋 View Tickets", "📁 Bulk Import", "📊 Export Data"])
    else:
        tab1, tab3 = st.tabs(["📋 View Tickets", "📊 Export Data"])
        tab2 = None
    
    with tab1:
        # Filters and controls
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            status_filter = st.selectbox("Status", ["All", "open", "in_progress", "resolved", "closed"])
        with col2:
            if st.button("🔄 Refresh"):
                st.rerun()
        with col3:
            if st.session_state.user[4] in ['admin', 'manager']:
                if st.button("📊 Analytics"):
                    st.session_state.page = 'analytics'
                    st.rerun()
        
        # Get and display tickets
        tickets_df = get_tickets(st.session_state.user[0], st.session_state.user[4], status_filter)
        
        if not tickets_df.empty:
            st.subheader(f"📋 Tickets ({len(tickets_df)} found)")
            
            for _, ticket in tickets_df.iterrows():
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                    
                    with col1:
                        st.markdown(f"**#{ticket['id']} - {ticket['title']}**")
                        st.write(f"{ticket['description'][:100]}..." if len(ticket['description']) > 100 else ticket['description'])
                        st.caption(f"Created by: {ticket['created_by_name']} | Assigned to: {ticket['assigned_to_name'] or 'Unassigned'}")
                    
                    with col2:
                        status_class = f"status-{ticket['status']}"
                        st.markdown(f'<span class="{status_class}">{ticket["status"].upper()}</span>', unsafe_allow_html=True)
                    
                    with col3:
                        priority_class = f"priority-{ticket['priority']}"
                        st.markdown(f'<span class="{priority_class}">{ticket["priority"].upper()}</span>', unsafe_allow_html=True)
                    
                    with col4:
                        if st.session_state.user[4] in ['admin', 'manager'] or ticket['assigned_to'] == st.session_state.user[0]:
                            action = st.selectbox("Action", ["Select", "In Progress", "Resolved", "Closed"], key=f"action_{ticket['id']}")
                            if action != "Select":
                                update_ticket_status(ticket['id'], action.lower().replace(" ", "_"), st.session_state.user[0])
                                st.success(f"✅ Ticket updated to {action}")
                                time.sleep(1)
                                st.rerun()
                    
                    # SLA indicator
                    if ticket['sla_deadline']:
                        try:
                            sla_time = datetime.datetime.strptime(ticket['sla_deadline'], '%Y-%m-%d %H:%M:%S')
                            time_left = sla_time - datetime.datetime.now()
                            if time_left.total_seconds() < 0:
                                st.error("⚠️ SLA OVERDUE!")
                            elif time_left.total_seconds() < 3600:
                                st.warning(f"⏰ SLA expires in {time_left}")
                            else:
                                st.info(f"📅 SLA: {sla_time.strftime('%m/%d %H:%M')}")
                        except:
                            pass
                    
                    st.divider()
        else:
            st.info("No tickets found.")
    
    # FIXED: CSV Import Tab
    if tab2:  # Only for admin/manager
        with tab2:
            st.markdown('<div class="import-section">', unsafe_allow_html=True)
            st.markdown("### 📁 Bulk Import Tickets from CSV")
            st.markdown("Upload a CSV file to create multiple tickets at once. The AI will help classify any missing information.")
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Sample CSV download
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("#### 📋 CSV Format Requirements:")
                st.markdown("""
                **Required columns:**
                - `title` - Ticket title (required)
                - `description` - Detailed description (required)
                
                **Optional columns:**
                - `category` - Will be AI-classified if empty
                - `priority` - Will be AI-classified if empty  
                - `assigned_to` - Username to assign ticket (use 'agent1')
                """)
            
            with col2:
                st.markdown("#### 📥 Download Sample Template:")
                sample_csv = generate_sample_csv()
                st.download_button(
                    "📥 Download Sample CSV", 
                    sample_csv,
                    "sample_tickets.csv",
                    "text/csv",
                    help="Download a sample CSV file to see the correct format"
                )
            
            st.markdown("---")
            
            # FIXED: File upload with proper processing
            uploaded_file = st.file_uploader("📤 Choose CSV file", type=['csv'], help="Upload your tickets CSV file")
            
            if uploaded_file is not None:
                try:
                    # Read file content as string
                    file_content = uploaded_file.read().decode('utf-8')
                    
                    # Preview data
                    preview_df = pd.read_csv(io.StringIO(file_content))
                    
                    st.markdown("#### 👀 Data Preview:")
                    st.dataframe(preview_df.head(10), use_container_width=True)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"📊 Found {len(preview_df)} rows to import")
                        st.info(f"📋 Columns: {', '.join(preview_df.columns.tolist())}")
                    
                    with col2:
                        if st.button("🚀 Import Tickets", type="primary", key="import_btn"):
                            st.markdown("### 🔄 Processing Import...")
                            
                            # Process import
                            success, errors, imported_count = process_csv_import(file_content, st.session_state.user[0])
                            
                            if success and imported_count > 0:
                                st.markdown(f'<div class="success-msg">🎉 Successfully imported {imported_count} tickets!</div>', unsafe_allow_html=True)
                                
                                if errors:
                                    st.warning("⚠️ Some rows had issues:")
                                    for error in errors:
                                        st.write(f"• {error}")
                                
                                # Show success and refresh
                                time.sleep(2)
                                st.rerun()
                                
                            else:
                                st.markdown('<div class="error-msg">❌ Import failed or no tickets were imported!</div>', unsafe_allow_html=True)
                                if errors:
                                    for error in errors:
                                        st.write(f"• {error}")
                
                except Exception as e:
                    st.error(f"❌ **Error reading CSV file:** {str(e)}")
                    st.write("**Please check that:**")
                    st.write("• Your file is a valid CSV format")
                    st.write("• The file has 'title' and 'description' columns")
                    st.write("• The file is not corrupted or empty")
    
    # Export tab
    with tab3:
        st.markdown("### 📊 Export Ticket Data")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📥 Download Options:")
            csv_data = export_tickets_csv()
            st.download_button(
                "📥 Export All Tickets (CSV)", 
                csv_data, 
                f"tickets_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                "text/csv",
                help="Download all tickets as CSV file"
            )
        
        with col2:
            st.markdown("#### 📋 Export Information:")
            st.info("""
            **Exported data includes:**
            - Ticket ID, Title, Description
            - Status, Priority, Category  
            - Creation date and creator
            - Assignment information
            """)

# Create ticket page
def create_ticket_page():
    st.markdown('<div class="main-header">➕ Create New Ticket</div>', unsafe_allow_html=True)
    
    with st.form("ticket_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            title = st.text_input("Ticket Title*")
            category = st.selectbox("Category", ["Auto-classify", "network", "hardware", "software", "email", "database", "security", "access", "communication"])
            description = st.text_area("Description*", height=150)
        
        with col2:
            st.markdown("### 🤖 AI Classification Preview")
            if title and description:
                pred_cat, pred_pri, confidence = classifier.classify_ticket(title, description)
                st.info(f"**Category:** {pred_cat}")
                st.info(f"**Priority:** {pred_pri}")
                st.info(f"**Confidence:** {confidence:.0%}")
        
        if st.form_submit_button("Create Ticket", use_container_width=True):
            if title and description:
                ticket_id, priority, confidence = create_ticket(title, description, category, st.session_state.user[0])
                st.success(f"✅ Ticket #{ticket_id} created! Priority: {priority.upper()}")
                time.sleep(2)
                st.session_state.page = 'tickets'
                st.rerun()
            else:
                st.error("Title and description are required")

# FIXED: Analytics page with proper None handling
def analytics_page():
    if st.session_state.user[4] not in ['admin', 'manager']:
        st.error("Access denied. Manager/Admin role required.")
        return
    
    st.markdown('<div class="main-header">📊 Advanced Analytics</div>', unsafe_allow_html=True)
    
    conn = get_db()
    
    # Performance metrics with proper None handling
    col1, col2, col3, col4 = st.columns(4)
    
    # Average resolution time - FIXED
    avg_resolution = pd.read_sql_query("""SELECT AVG(CAST((julianday(resolved_at) - julianday(created_at)) * 24 AS REAL)) as hours
                                          FROM tickets WHERE resolved_at IS NOT NULL""", conn)
    
    # Proper None handling
    if not avg_resolution.empty and avg_resolution.iloc[0]['hours'] is not None:
        avg_hours = avg_resolution.iloc[0]['hours']
        col1.metric("Avg Resolution Time", f"{avg_hours:.1f}h")
    else:
        col1.metric("Avg Resolution Time", "N/A")
    
    # SLA compliance - FIXED
    sla_compliance = pd.read_sql_query("""SELECT COUNT(CASE WHEN resolved_at <= sla_deadline THEN 1 END) * 100.0 / COUNT(*) as rate
                                         FROM tickets WHERE resolved_at IS NOT NULL""", conn)
    
    if not sla_compliance.empty and sla_compliance.iloc[0]['rate'] is not None:
        sla_rate = sla_compliance.iloc[0]['rate']
        col2.metric("SLA Compliance", f"{sla_rate:.1f}%")
    else:
        col2.metric("SLA Compliance", "N/A")
    
    # Tickets per day - FIXED
    daily_rate = pd.read_sql_query("SELECT COUNT(*) / 7.0 as rate FROM tickets WHERE created_at >= date('now', '-7 days')", conn)
    
    if not daily_rate.empty and daily_rate.iloc[0]['rate'] is not None:
        rate = daily_rate.iloc[0]['rate']
        col3.metric("Tickets/Day", f"{rate:.1f}")
    else:
        col3.metric("Tickets/Day", "0.0")
    
    # Agent workload - FIXED
    agent_load = pd.read_sql_query("""SELECT AVG(load) as avg_load FROM 
                                     (SELECT COUNT(*) as load FROM tickets WHERE status IN ('open','in_progress') GROUP BY assigned_to)""", conn)
    
    if not agent_load.empty and agent_load.iloc[0]['avg_load'] is not None:
        avg_load = agent_load.iloc[0]['avg_load']
        col4.metric("Avg Agent Load", f"{avg_load:.1f}")
    else:
        col4.metric("Avg Agent Load", "0.0")
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🕒 Resolution Time by Priority")
        resolution_data = pd.read_sql_query("""SELECT priority, AVG(CAST((julianday(resolved_at) - julianday(created_at)) * 24 AS REAL)) as hours
                                              FROM tickets WHERE resolved_at IS NOT NULL GROUP BY priority""", conn)
        if not resolution_data.empty:
            # Filter out None values
            resolution_data = resolution_data.dropna()
            if not resolution_data.empty:
                fig = px.bar(resolution_data, x='priority', y='hours', color='priority',
                            color_discrete_map={'critical': '#e74c3c', 'high': '#f39c12', 'medium': '#f1c40f', 'low': '#9b59b6'})
                fig.update_layout(showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No resolution data available yet.")
        else:
            st.info("No resolution data available yet.")
    
    with col2:
        st.subheader("📊 Ticket Volume Trend")
        trend_data = pd.read_sql_query("""SELECT date(created_at) as date, COUNT(*) as count
                                         FROM tickets WHERE created_at >= date('now', '-30 days')
                                         GROUP BY date(created_at) ORDER BY date""", conn)
        if not trend_data.empty:
            fig = px.line(trend_data, x='date', y='count', 
                         title="Daily Ticket Creation (Last 30 Days)",
                         markers=True)
            fig.update_traces(line_color='#3498db', marker_color='#e74c3c')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No trend data available yet.")
    
    conn.close()

# Main application
def main():
    if not st.session_state.authenticated:
        auth_page()
    else:
        # Sidebar navigation
        with st.sidebar:
            st.markdown(f"### 👋 Welcome, {st.session_state.user[5]}")
            st.markdown(f"**Role:** {st.session_state.user[4].replace('_', ' ').title()}")
            st.markdown(f"**Department:** {st.session_state.user[6] or 'N/A'}")
            st.divider()
            
            # Navigation
            if st.button("📊 Dashboard", use_container_width=True):
                st.session_state.page = 'dashboard'
            if st.button("🎫 Tickets", use_container_width=True):
                st.session_state.page = 'tickets'
            if st.button("➕ Create Ticket", use_container_width=True):
                st.session_state.page = 'create'
            if st.session_state.user[4] in ['admin', 'manager']:
                if st.button("📈 Analytics", use_container_width=True):
                    st.session_state.page = 'analytics'
            
            st.divider()
            if st.button("🚪 Logout", use_container_width=True):
                st.session_state.authenticated = False
                st.session_state.user = None
                st.session_state.page = 'login'
                st.rerun()
        
        # Main content
        if st.session_state.page == 'dashboard':
            dashboard_page()
        elif st.session_state.page == 'tickets':
            tickets_page()
        elif st.session_state.page == 'create':
            create_ticket_page()
        elif st.session_state.page == 'analytics':
            analytics_page()

if __name__ == "__main__":
    main()