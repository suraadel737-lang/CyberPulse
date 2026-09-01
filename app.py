import streamlit as st
import pandas as pd
import numpy as np
import requests
import io
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# 1. إعدادات الصفحة
st.set_page_config(page_title="AI Cyber Threat Detection & Enterprise IPS", page_icon="🛡️", layout="wide")

# 2. تصميم CSS فاتح ونظيف مع تأثيرات تفاعلية ورادار الطوارئ
st.markdown("""
<style>
    .stApp { background-color: #f8fafc; color: #0f172a; }
    [data-testid="stSidebar"] { background-color: #ffffff; border-right: 1px solid #e2e8f0; }
    .header-card { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); padding: 24px; border-radius: 12px; color: #ffffff; margin-bottom: 24px; }
    div.stButton > button { width: 100%; border-radius: 10px; padding: 12px; border: 1px solid #cbd5e1; background-color: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    div.stButton > button:hover { border-color: #3b82f6; background-color: #eff6ff; }
    .mitigation-panel { background-color: #ffffff; border: 2px solid #ef4444; border-radius: 12px; padding: 20px; margin-top: 15px; box-shadow: 0 4px 6px -1px rgba(239,68,68,0.1); }
    .emergency-btn > button { background-color: #dc2626 !important; color: white !important; font-weight: bold; border: 2px solid #991b1b !important; }
    .emergency-btn > button:hover { background-color: #b91c1c !important; }
    
    @keyframes radar-pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 15px rgba(239, 68, 68, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    .radar-alert-box {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        border: 2px dashed #dc2626;
        border-radius: 12px;
        padding: 15px;
        text-align: center;
        color: #991b1b;
        font-weight: bold;
        animation: radar-pulse 2s infinite;
        margin-bottom: 15px;
    }
</style>
""", unsafe_allow_html=True)

# رابط الـ API المحلي الذي قمنا بتشغيله عبر FastAPI
API_URL = "http://127.0.0.1:8000/predict"

# 3. إدارة حالة الصفحة (Session State)
if 'df' not in st.session_state:
    st.session_state.df = None
if 'selected_card' not in st.session_state:
    st.session_state.selected_card = "MAIN"
if 'mitigated_ports' not in st.session_state:
    st.session_state.mitigated_ports = set()
if 'mitigated_attacks' not in st.session_state:
    st.session_state.mitigated_attacks = set()
if 'blacklisted_ips' not in st.session_state:
    st.session_state.blacklisted_ips = set()
if 'audit_logs' not in st.session_state:
    st.session_state.audit_logs = []
if 'radar_active' not in st.session_state:
    st.session_state.radar_active = False

def log_action(action_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.audit_logs.append({
        "Timestamp": timestamp,
        "Analyst": "SOC_Admin",
        "Action Type": action_type,
        "Details": details
    })

# 4. التحقق من اتصال الـ API بدلاً من تحميل النموذج محلياً
@st.cache_resource
def check_api_connection():
    try:
        response = requests.get("http://127.0.0.1:8000/", timeout=3)
        return response.status_code == 200
    except:
        return False

api_connected = check_api_connection()

# 5. الهيدر الرئيسي
st.markdown("""
<div class="header-card">
    <h1 style="margin:0; font-size: 28px; color: #ffffff;">🛡️ نظام الذكاء الاصطناعي لكشف الاختراقات والاستجابة الفورية (NIDS/IPS)</h1>
    <p style="margin:4px 0 0 0; font-size: 15px; color: #dbeafe;">منصة تحليل التهديدات الأمنية المتقدمة وإدارة الاستجابة الآلية للحوادث (SOC) - معمارية FastAPI & Streamlit</p>
</div>
""", unsafe_allow_html=True)

# 6. القائمة الجانبية (مع ترتيب حالة الـ Backend API وتنسيقها تحت بعضها بسطر جديد وبشكل واضح)
st.sidebar.header("🕹️ لوحة التحكم والرادار")

if api_connected:
    st.sidebar.markdown("""
        <div style="background-color: #ecfdf5; border: 1px solid #10b981; padding: 12px; border-radius: 8px; color: #065f46; font-size: 13px; font-weight: bold; text-align: center; line-height: 1.8;">
            🛡️ مركز العمليات الأمنية (SOC)<br>
            حالة الاتصال: <span style="color: #047857;">متصل بالـ Backend API بنجاح</span><br>
            <span style="font-size: 11px; font-weight: normal; color: #047857;">جاهز لرصد الحزم وتفعيل الاستجابة الآلية (IPS)</span>
        </div>
    """, unsafe_allow_html=True)
else:
    st.sidebar.markdown("""
        <div style="background-color: #fef2f2; border: 1px solid #ef4444; padding: 12px; border-radius: 8px; color: #991b1b; font-size: 13px; font-weight: bold; text-align: center; line-height: 1.8;">
            ❌ خطأ في الاتصال بالـ Backend API<br>
            حالة الاتصال: <span style="color: #dc2626;">غير متصل (Disconnected)</span><br>
            <span style="font-size: 11px; font-weight: normal; color: #b91c1c;">تأكد من تشغيل أمر uvicorn api:app --reload</span>
        </div>
    """, unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown("##### 📡 اختبار رادار التهديدات البصري")
if st.sidebar.button("🎯 انقر لتفعيل نبض الرادار الطارئ"):
    st.session_state.radar_active = True
    st.sidebar.success("تم تفعيل رادار الطوارئ بنجاح!")

source_option = st.sidebar.radio("اختر طريقة الفحص:", ["محاكاة هجوم حية", "رفع ملف CSV"])

if source_option == "محاكاة هجوم حية":
    if st.sidebar.button("🚀 تشغيل محاكاة فورية"):
        np.random.seed(42)
        n_samples = 500
        
        ports_list = [80, 443, 22, 21, 8080, 53, 3389, 1433, 3306, 25]
        ip_pool = [f"192.168.1.{np.random.randint(10, 200)}" for _ in range(n_samples)]
        
        sim_data = {
            'Source IP': ip_pool,
            'Destination Port': np.random.choice(ports_list, n_samples),
            'Flow Duration': np.random.choice([500, 100000, 5000000], n_samples),
            'Total Fwd Packets': np.random.choice([2, 50, 500], n_samples),
            'Total Backward Packets': np.random.choice([0, 20, 200], n_samples),
            'Total Length of Fwd Packets': np.random.choice([100, 5000, 50000], n_samples),
        }
        
        # حل نهائي لخطأ الـ Scalar values عبر تمرير index صريح لـ Pandas DataFrame
        df_temp = pd.DataFrame(sim_data, index=range(n_samples))
        
        try:
            csv_bytes = df_temp.to_csv(index=False).encode('utf-8')
            files = {"file": ("simulation.csv", csv_bytes, "text/csv")}
            res = requests.post(API_URL, files=files)
            
            if res.status_code == 200:
                df_temp = pd.DataFrame(res.json())
                cols = ['Predicted_Attack_Type', 'Source IP'] + [col for col in df_temp.columns if col not in ['Predicted_Attack_Type', 'Source IP']]
                st.session_state.df = df_temp[cols]
                st.session_state.selected_card = "MAIN"
                st.session_state.mitigated_ports = set()
                st.session_state.mitigated_attacks = set()
                st.session_state.blacklisted_ips = set()
                st.session_state.audit_logs = []
                log_action("SYSTEM", "تم تشغيل محاكاة الهجمات الحية وتحليلها عبر الـ API بنجاح.")
            else:
                st.sidebar.error(f"خطأ في الـ API: {res.text}")
        except Exception as e:
            st.sidebar.error(f"تعذر الاتصال بالسيرفر لمعالجة المحاكاة: {e}")

else:
    uploaded_file = st.sidebar.file_uploader("قم برفع ملف حزم البيانات (CSV)", type=["csv"])
    if uploaded_file is not None:
        try:
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/csv")}
            res = requests.post(API_URL, files=files)
            
            if res.status_code == 200:
                df_temp = pd.DataFrame(res.json())
                cols = ['Predicted_Attack_Type', 'Source IP'] + [col for col in df_temp.columns if col not in ['Predicted_Attack_Type', 'Source IP']]
                st.session_state.df = df_temp[cols]
                st.session_state.selected_card = "MAIN"
                st.session_state.mitigated_ports = set()
                st.session_state.mitigated_attacks = set()
                st.session_state.blacklisted_ips = set()
                st.session_state.audit_logs = []
                log_action("SYSTEM", f"تم رفع ملف الحزم وتحليله عبر الـ API بنجاح: {uploaded_file.name}")
            else:
                st.sidebar.error(f"خطأ في الـ API: {res.text}")
        except Exception as e:
            st.sidebar.error(f"تعذر إرسال الملف للـ API: {e}")

# 7. عرض البيانات والتفاعلية المباشرة
df = st.session_state.df

if df is not None and api_connected:
    total = len(df)
    benign_df = df[df['Predicted_Attack_Type'] == 'BENIGN']
    
    threat_df = df[
        (df['Predicted_Attack_Type'] != 'BENIGN') & 
        (~df['Destination Port'].isin(st.session_state.mitigated_ports)) &
        (~df['Predicted_Attack_Type'].isin(st.session_state.mitigated_attacks)) &
        (~df['Source IP'].isin(st.session_state.blacklisted_ips))
    ]
    
    benign = len(benign_df)
    attacks = len(threat_df)
    threat_rate = (attacks / total) * 100 if total > 0 else 0

    st.markdown("##### 💡 انقر على أي بطاقة أدناه لاستعراض تفاصيلها التحليلية وإتاحة وحدة المعالجة والاستجابة الفورية:")
    k1, k2, k3, k4 = st.columns(4)
    
    if k1.button(f"📦 إجمالي الحزم\n\n### {total:,}"):
        st.session_state.selected_card = "TOTAL"
    if k2.button(f"🟢 حركة سليمة\n\n### {benign:,}"):
        st.session_state.selected_card = "BENIGN"
    if k3.button(f"🚨 التهديدات النشطة\n\n### {attacks:,}"):
        st.session_state.selected_card = "ATTACKS"
    if k4.button(f"⚠️ نسبة الخطر\n\n### {threat_rate:.1f}%"):
        st.session_state.selected_card = "RATE"

    st.markdown("<br>", unsafe_allow_html=True)

    if threat_rate > 25 or st.session_state.radar_active:
        st.markdown("""
            <div class="radar-alert-box">
                🚨 📡 [CYBER RADAR ALERT] تنبيه أمني نشط: تم رصد حزم خبيثة تتخطى الحدود المسموح بها! جاري مراقبة وتأمين الشبكة.
            </div>
        """, unsafe_allow_html=True)
        st.session_state.radar_active = False
    else:
        st.markdown("""
            <div style="background: #ecfdf5; border: 1px solid #10b981; border-radius: 12px; padding: 12px; text-align: center; color: #065f46; font-weight: bold; margin-bottom: 15px;">
                🛡️ 🟢 [SYSTEM SECURE] رادار الشبكة يعمل بوضع الأمان التام ولا توجد اختراقات حرجة.
            </div>
        """, unsafe_allow_html=True)

    if len(st.session_state.mitigated_ports) > 0 or len(st.session_state.mitigated_attacks) > 0 or len(st.session_state.blacklisted_ips) > 0:
        st.success(f"🛡️ **سجل قواعد جدار الحماية المفعلة (Active Firewall Rules):** "
                   f"المنافذ المغلقة: `{list(st.session_state.mitigated_ports)}` | "
                   f"الـ IP المحظورة: `{list(st.session_state.blacklisted_ips)}` | "
                   f"الهجمات المعزولة: `{list(st.session_state.mitigated_attacks)}`")

    if st.session_state.selected_card == "TOTAL":
        st.info("📦 **سجل كافة الحزم المفحوصة (السليمة والتهديدات):**")
        st.dataframe(df, use_container_width=True)
        if st.button("↩️ العودة للرئيسية"):
            st.session_state.selected_card = "MAIN"
            st.rerun()

    elif st.session_state.selected_card == "BENIGN":
        st.success("🟢 **تفاصيل الحزم السليمة (BENIGN) فقط:**")
        st.dataframe(benign_df, use_container_width=True)
        if st.button("↩️ العودة للرئيسية"):
            st.session_state.selected_card = "MAIN"
            st.rerun()

    elif st.session_state.selected_card in ["ATTACKS", "RATE"]:
        st.error(f"🚨 **سجل التهديدات النشطة المكتشفة ({attacks} هجوم) - نسبة الخطر: {threat_rate:.1f}%:**")
        st.dataframe(threat_df, use_container_width=True)
        
        if len(threat_df) > 0:
            st.markdown("<div class='mitigation-panel'>", unsafe_allow_html=True)
            st.markdown("### ⚡ وحدة الاستجابة الفورية وإنشاء قواعد جدار الحماية (Firewall & IP Blacklist)")
            col_m1, col_m2, col_m3 = st.columns(3)
            
            with col_m1:
                st.markdown("##### 1. حظر المنفذ المستهدف:")
                port_to_block = st.selectbox("اختر المنفذ:", sorted(threat_df['Destination Port'].unique()), key="click_port")
                if st.button("🔥 حظر المنفذ (Block Port)", key="btn_clk_p"):
                    st.session_state.mitigated_ports.add(port_to_block)
                    log_action("FIREWALL", f"تم حظر المنفذ المستهدف رقم: {port_to_block}")
                    st.toast(f"تم حظر المنفذ {port_to_block} بنجاح!", icon="🔥")
                    st.rerun()

            with col_m2:
                st.markdown("##### 2. حظر عنوان الـ IP المهاجم:")
                ip_to_block = st.selectbox("اختر عنوان الـ IP:", sorted(threat_df['Source IP'].unique()), key="click_ip")
                if st.button("🚫 حظر الـ IP (IP Blacklist)", key="btn_clk_ip"):
                    st.session_state.blacklisted_ips.add(ip_to_block)
                    log_action("IP_BLOCK", f"تم إضافة العنوان {ip_to_block} إلى القائمة السوداء للـ IPS")
                    st.toast(f"تم إدراج الـ IP {ip_to_block} في القائمة السوداء!", icon="🚫")
                    st.rerun()

            with col_m3:
                st.markdown("##### 3. حظر بصمة الهجوم كاملاً:")
                attack_to_block = st.selectbox("اختر نمط الهجوم:", sorted(threat_df['Predicted_Attack_Type'].unique()), key="click_att")
                if st.button("⚡ عزل نمط الهجوم", key="btn_clk_a"):
                    st.session_state.mitigated_attacks.add(attack_to_block)
                    log_action("SIGNATURE_BLOCK", f"تم حظر نمط الهجوم بالكامل: {attack_to_block}")
                    st.toast(f"تم حظر هجوم {attack_to_block}!", icon="🛡️")
                    st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("↩️ العودة للرئيسية"):
            st.session_state.selected_card = "MAIN"
            st.rerun()

    else:
        st.markdown("---")
        ind_col1, ind_col2, ind_col3 = st.columns([1, 2, 1])
        
        with ind_col1:
            st.markdown("##### 🎛️ إعدادات حساسية نظام الإنذار")
            sensitivity_threshold = st.slider("مستوى حد الإنذار المبكر (%)", min_value=1, max_value=50, value=25, step=1)
            
            if threat_rate > sensitivity_threshold:
                st.error("🚨 **تنبيه عالي: الشبكة تحت خطر حقيقي!**")
            else:
                st.success("🟢 **حالة الشبكة مستقرة وآمنة.**")

        with ind_col2:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=threat_rate,
                delta={'reference': sensitivity_threshold, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
                title={'text': "<b>مؤشر خطر الشبكة اللحظي (Interactive Risk Score)</b>", 'font': {'size': 16, 'color': '#1e3a8a'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                    'bar': {'color': "#ef4444" if threat_rate > sensitivity_threshold else "#3b82f6"},
                    'steps': [
                        {'range': [0, sensitivity_threshold], 'color': '#d1fae5'},
                        {'range': [sensitivity_threshold, 100], 'color': '#fee2e2'}
                    ],
                    'threshold': {
                        'line': {'color': "darkred", 'width': 4},
                        'thickness': 0.8,
                        'value': sensitivity_threshold
                    }
                }
            ))
            fig_gauge.update_layout(height=230, margin=dict(l=10, r=10, t=30, b=10))
            st.plotly_chart(fig_gauge, use_container_width=True)

        with ind_col3:
            st.markdown("##### ⚡ الإجراء الاستباقي السريع")
            st.markdown("زر الطوارئ لعزل كافة التهديدات النشطة فوراً:")
            
            st.markdown('<div class="emergency-btn">', unsafe_allow_html=True)
            if st.button("🚨 تفعيل الطوارئ وعزل الكل"):
                if len(threat_df) > 0:
                    for p in threat_df['Destination Port'].unique():
                        st.session_state.mitigated_ports.add(p)
                    for ip in threat_df['Source IP'].unique():
                        st.session_state.blacklisted_ips.add(ip)
                    for a in threat_df['Predicted_Attack_Type'].unique():
                        st.session_state.mitigated_attacks.add(a)
                    log_action("EMERGENCY_LOCKDOWN", "تم تفعيل حالة الطوارئ القصوى وعزل كافة المنافذ والـ IPs والتهديدات النشطة!")
                    st.success("تم تنفيذ الإغلاق الطارئ بنجاح وتأمين البنية التحتية بالكامل!")
                    st.rerun()
                else:
                    st.info("لا توجد تهديدات نشطة تستدعي الإغلاق الطارئ.")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # إضافة التبويب الجديد الخاص بدليل استخدام المنصة للمستخدم/اللجنة
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 التحليل البياني للتهديدات", 
            "🚨 سجل التهديدات وعزل الـ IP", 
            "📋 سجل تدقيق أحداث الـ SIEM وتصدير التقارير",
            "📄 تقرير الحادث الآلي (Post-Mortem Report)",
            "📖 دليل استخدام المنصة (User Guide)"
        ])

        with tab1:
            c1, c2 = st.columns(2)
            attack_counts = threat_df['Predicted_Attack_Type'].value_counts().reset_index()
            attack_counts.columns = ['Attack_Type', 'Count']

            with c1:
                st.markdown("##### توزيع أنواع التهديدات النشطة")
                if len(attack_counts) > 0:
                    fig_pie = px.pie(attack_counts, names='Attack_Type', values='Count', hole=0.4, color_discrete_sequence=px.colors.qualitative.Set2)
                    fig_pie.update_layout(template="plotly_white")
                    st.plotly_chart(fig_pie, use_container_width=True)
                else:
                    st.success("🎉 لا توجد هجمات نشطة حالياً. تم حظر جميع التهديدات!")

            with c2:
                st.markdown("##### أعداد التهديدات حسب النوع")
                if len(attack_counts) > 0:
                    fig_bar = px.bar(attack_counts, x='Attack_Type', y='Count', color='Attack_Type', text_auto=True, color_discrete_sequence=px.colors.qualitative.Safe)
                    fig_bar.update_layout(template="plotly_white")
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.success("🎉 تم تحييد جميع المخاطر بنجاح.")

        with tab2:
            st.markdown("##### 🚨 قائمة الهجمات المكتشفة ومصادر عناوين الـ IP المهاجمة")
            if len(threat_df) > 0:
                st.warning("⚠️ يمكنك متابعة عناوين الـ IP للمهاجمين وإدراجها في القائمة السوداء للـ IPS فوراً:")
                #st.dataframe(threat_df[['Predicted_Attack_Type', 'Source IP', 'Destination Port', 'Flow Duration']], use_container_width=True)
                # بدلاً من استدعاء أعمدة قد تكون غير موجودة، سنعرض الجدول كاملاً أو الأعمدة المتاحة بأمان:
                st.dataframe(threat_df, use_container_width=True)
                col_ip_1, col_ip_2 = st.columns(2)
                with col_ip_1:
                    ip_select = st.selectbox("اختر عنوان الـ IP لحظره وإضافته للقائمة السوداء:", sorted(threat_df['Source IP'].unique()), key="tab2_ip")
                    if st.button("🚫 إدراج في القائمة السوداء (Blacklist IP)", key="btn_b_ip"):
                        st.session_state.blacklisted_ips.add(ip_select)
                        log_action("IP_BLACKLIST", f"إدراج الـ IP {ip_select} في القائمة السوداء للشبكة.")
                        st.success("تم حظر الـ IP بنجاح وعزل مصدر الهجوم!")
                        st.rerun()
            else:
                st.success("🎉 لا توجد هجمات نشطة حالياً أو تم حظر كافة عناوين الـ IP الخبيثة.")

            st.markdown("---")
            st.markdown("##### 🔓 إدارة القائمة السوداء ورفع الحظر (IP Unblock Management)")
            if len(st.session_state.blacklisted_ips) > 0:
                st.info("عناوين الـ IP المحظورة حالياً في النظام:")
                unblock_ip_select = st.selectbox("اختر عنوان IP لإزالة الحظر عنه:", sorted(list(st.session_state.blacklisted_ips)), key="unblock_ip_key")
                if st.button("✅ رفع الحظر (Unblock IP)", key="btn_unblock_ip"):
                    st.session_state.blacklisted_ips.remove(unblock_ip_select)
                    log_action("IP_UNBLOCK", f"تم إزالة الحظر عن العنوان {unblock_ip_select} وإعادته للشبكة.")
                    st.success(f"تم رفع الحظر عن الـ IP {unblock_ip_select} بنجاح!")
                    st.rerun()
            else:
                st.caption("لا توجد أي عناوين IP محظورة حالياً في القائمة السوداء.")

        with tab3:
            st.markdown("##### 📋 وحدة سجل الأحداث الحية والتدقيق (Live SIEM Audit Logs)")
            st.info("سجل زمني دقيق لكل العمليات والإجراءات الأمنية التي قام بها النظام أو المحلل:")
            
            if len(st.session_state.audit_logs) > 0:
                df_logs = pd.DataFrame(st.session_state.audit_logs)
                st.dataframe(df_logs, use_container_width=True)
                
                csv_data = df_logs.to_csv(index=False, encoding='utf-8-sig').encode('utf-8-sig')
                st.download_button(
                    label="📥 تحميل وتصدير تقرير التدقيق (SIEM Audit CSV)",
                    data=csv_data,
                    file_name="soc_audit_report.csv",
                    mime="text/csv"
                )
            else:
                st.warning("لم يتم تسجيل أي إجراءات حتى الآن. تفاعل مع لوحة التحكم لتوليد سجلات التدقيق.")

        with tab4:
            st.markdown("##### 📄 تقرير تحليل الحادث الأمني الشامل (Comprehensive Incident Post-Mortem Report)")
            st.markdown("وثيقة تحليلية وتقنية متقدمة تُوثق حالة الشبكة، كفاءة الاستجابة الفورية، الأنماط الهجومية المرصودة، والتوصيات المعمارية للاستجابة للحوادث:")
            
            most_frequent_attack = threat_df['Predicted_Attack_Type'].mode()[0] if len(threat_df) > 0 else "None"
            risk_classification = "حرج (Critical - يتطلب تدخل عاجل)" if threat_rate > sensitivity_threshold else "مستقر وتحت السيطرة (Stable & Monitored)"
            
            rep_c1, rep_c2, rep_c3, rep_c4 = st.columns(4)
            rep_c1.metric("📦 إجمالي الحزم المفحوصة", f"{total:,}")
            rep_c2.metric("🚨 الحزم الخبيثة المكتشفة", f"{attacks:,}")
            rep_c3.metric("⚠️ معدل الخطورة العام", f"{threat_rate:.2f}%")
            rep_c4.metric("🛡️ إجراءات الحماية الفعالة", f"{len(st.session_state.blacklisted_ips) + len(st.session_state.mitigated_ports)} إجراء")
            
            st.markdown("---")
            
            st.markdown("### 📊 الملخص التنفيذي والتشخيص الفني (Executive Summary & Technical Diagnostics)")
            st.markdown(f"""
            * **حالة المنظومة الأمنية:** النظام يعمل بكفاءة عبر خوارزميات التعلم الآلي عبر خادم الـ API الخارجي. الحالة الراهنة مصنفة كالتالي: **{risk_classification}**.
            * **نوع الهجوم السائد (Dominant Attack Vector):** `{most_frequent_attack}`، وهو النمط الأكثر رصداً ضمن الحزم الواردة ويتطلب مراقبة مستمرة للـ Signatures الخاصة به.
            * **كفاءة الاستجابة الآلية (IPS Mitigation Status):** 
              * عدد المنافذ المعزولة: **{len(st.session_state.mitigated_ports)} منفذ** (`{list(st.session_state.mitigated_ports) if st.session_state.mitigated_ports else 'لا يوجد'}`)
              * عناوين الـ IP المدرجة في القائمة السوداء: **{len(st.session_state.blacklisted_ips)} عنوان** (`{list(st.session_state.blacklisted_ips) if st.session_state.blacklisted_ips else 'لا يوجد'}`)
              * أنماط الهجمات المعزولة كلياً: **{len(st.session_state.mitigated_attacks)} نمط** (`{list(st.session_state.mitigated_attacks) if st.session_state.mitigated_attacks else 'لا يوجد'}`)
            """)
            
            st.markdown("---")
            st.markdown("### 🔬 تحليل السلوك الشبكي وتقييم المخاطر (Network Behavioral Analysis & Risk Assessment)")
            st.markdown("""
            1. **معدل التدفق والضغط على البنية التحتية (Flow Duration & Packets):**
               * يتم تحليل خصائص الحزم مثل مدة التدفق (`Flow Duration`) وحجم الحزم المرسلة والمستقبلية عبر الـ API.
            2. **سلوك نظام الحماية والاستجابة الفورية (IPS Action Loop):**
               * عند اكتشاف أي انحراف عن السلوك الطبيعي (`BENIGN`) وتخطيه لعتبة الحساسية المحددة (`Threshold`), يفعل النظام آليات العزل الفوري.
            3. **التدقيق المعماري والأمني (SIEM Audit Trail):**
               * كافة العمليات التي تتم عبر المشرف يتم تسجيلها بزمني لضمان تتبع الهجمات (Forensic Analysis).
            """)
            
            st.markdown("---")
            st.markdown("### 💡 التوصيات الاستراتيجية وتصلبات النظام المستقبلية (Strategic Hardening Recommendations)")
            st.markdown("""
            * **تحديث نماذج الذكاء الاصطناعي دورياً:** يُنصح بإعادة تدريب النموذج في سيرفر الـ API دورياً.
            * **تعزيز سياسات جدار الحماية (Firewall Hardening):** الاعتماد على القائمة السوداء التلقائية للـ IPs لتقليل وقت الاستجابة (MTTR).
            * **مراقبة المنافذ الحساسة:** تشديد الرقابة على المنافذ الشائعة الاستخدام في الهجمات.
            """)
            
            report_text = f"""==================================================
    تقرير تحليل الحادث الأمني الآلي (POST-MORTEM REPORT)
    منصة الذكاء الاصطناعي لكشف الاختراقات والاستجابة (NIDS/IPS)
==================================================
تاريخ ووقت التقرير: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
اسم المشرف: SOC_Admin
حالة المنظومة: {risk_classification}

1. الملخص الإحصائي:
- إجمالي الحزم المفحوصة: {total:,}
- الحزم الخبيثة المكتشفة: {attacks:,}
- معدل الخطر العام: {threat_rate:.2f}%
- عتبة الإنذار المحددة: {sensitivity_threshold}%

2. حالة الإجراءات والتحصينات الأمنية:
- المنافذ المغلقة: {list(st.session_state.mitigated_ports) if st.session_state.mitigated_ports else 'لا يوجد'}
- عناوين الـ IP في القائمة السوداء: {list(st.session_state.blacklisted_ips) if st.session_state.blacklisted_ips else 'لا يوجد'}
- أنماط الهجمات المعزولة: {list(st.session_state.mitigated_attacks) if st.session_state.mitigated_attacks else 'لا يوجد'}
- نوع الهجوم السائد: {most_frequent_attack}
=================================================="""

            st.download_button(
                label="📥 تصدير وتحميل تقرير الحادث الأمني للإدارة (Post-Mortem .TXT)",
                data=report_text.encode('utf-8-sig'),
                file_name=f"incident_post_mortem_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

        with tab5:
            st.markdown("##### 📖 دليل التشغيل الشامل ودليل المشغل لمنصة NIDS/IPS")
            st.markdown("""
            مرحباً بك في دليل التشغيل التقني لمنصة **AI Cyber Threat Detection & Enterprise IPS**. يوضح هذا المستند الخطوات العملية والتعليمات البرمجية والتشغيلية لإدارة مراكز العمليات الأمنية (SOC) ومراقبة التدفقات الشبكية بكفاءة عالية.

            ---

            ### 1️⃣ إعداد وتشغيل الخادم الخلفي (Backend API Initialization)
            * **متطلبات التشغيل:** يعتمد النظام في المعالجة وتحليل النماذج على خدمة خادم `FastAPI`. تأكد من تفعيل بيئة العمل الافتراضية وتثبيت المكتبات المطلوبة.
            * **أمر التشغيل البرمجي:** افتح موجه الأوامر (`Terminal`) في مسار المشروع وقم بتشغيل الخادم المحلي عبر الأمر التالي:
              ```bash
              uvicorn api:app --reload
              ```
            * **التحقق من الاتصال:** راقب مؤشر الحالة في الشريط الجانبي الأيسر؛ حيث يدل ظهور لون الأخضر (`متصل بالـ Backend API بنجاح`) على جاهزية الخادم لاستقبال حزم البيانات ومعالجتها عبر النموذج الذكي.

            ### 2️⃣ معالجة وتغذية البيانات الشبكية (Data Ingestion Pipeline)
            تتيح المنصة طريقتين أساسيتين لإدخال وتحليل حركة مرور الشبكة:
            * **محاكاة هجوم حية (Live Attack Simulation):** النقر على زر `🚀 تشغيل محاكاة فورية` في القائمة الجانبية يولد عينة بيانات افتراضية تمثل تدفقات شبكية حقيقية (تحتوي على حزم سليمة BENIGN وأخرى خبيثة لمختلف أنواع الهجمات)، ويقوم بإرسالها برمجياً إلى الـ API لتصنيفها.
            * **رفع ملفات الحزم (CSV Upload):** تتيح خاصية رفع الملفات إمكانية إسقاط ملفات التدفقات الشبكية بصيغة CSV ليقوم النظام بتحليلها وإسقاط النتائج فوراً على لوحة التحكم.

            ### 3️⃣ مراقبة لوحة التحكم والتحكم التشغيلي (SOC Dashboard & Operations)
            * **البطاقات الإحصائية التفاعلية:** تعرض الملخص العام لإجمالي الحزم المفحوصة، الحركة السليمة، التهديدات النشطة، ومعدل الخطورة العام. النقر على أي بطاقة يفتح الجدول التحليلي المخصص لها.
            * **مؤشر الخطر اللحظي (Interactive Risk Score):** عداد بصري يوضح نسبة التهديدات الحالية مقارنة عتبة الإنذار المبكر المحددة عبر شريط الحساسية (Sensitivity Slider).
            * **رادار التهديدات ونظام الطوارئ:** يتفعل تلقائياً عند تجاوز معدلات الخطر للحدود الآمنة، مع وجود زر `🚨 تفعيل الطوارئ وعزل الكل` لتنفيذ حظر شامل وتأمين البنية التحتية بنقرة واحدة عند وقوع هجوم سيبراني واسع النطاق.

            ### 4️⃣ إدارة الاستجابة الفورية وأنظمة الحماية (IPS & Firewall Mitigation)
            تتيح لوحة الاستجابة اتخاذ تدابير وقائية فورية لاحتواء المخاطر:
            * **حظر المنافذ (Block Port):** إيقاف الاتصالات الواردة عبر المنافذ المستهدفة من قبل المهاجمين.
            * **القائمة السوداء لعناوين الـ IP (IP Blacklist):** عزل عناوين المصدر الخبيثة لمنع تكرار محاولات الاختراق، مع وجود خيار لاحق لإدارة ورفع الحظر (`Unblock IP`) عن العناوين في تبويب الإدارة.
            * **عزل بصمات الهجمات (Signature Blocking):** إيقاف أنماط الاختراقات المتكررة بناءً على التصنيف اللحظي للذكاء الاصطناعي.

            ### 5️⃣ سجلات التدقيق الجنائي وتصدير التقارير (SIEM Auditing & Reporting)
            * **سجل أحداث الـ SIEM الحية:** تتبع زمني دقيق لكل إجراء أمني قام به النظام أو المحلل، مع خيار لتصدير السجلات بصيغة `.csv` لأغراض التحليل الجنائي الرقمي (Forensic Analysis).
            * **تقرير الحادث الأمني (Post-Mortem Report):** تقرير فني شامل يوثق مقاييس الأداء، كفاءة الاستجابة، تحليل السلوك الشبكي، والتوصيات الاستراتيجية لتصلب النظام، وقابل للتصدير والتحميل كملف نصي (`.txt`) رسمي للاستخدام المؤسسي.
            """)

else:
    st.info("👈 تأكد من تشغيل الـ API أولاً، ثم انقر على زر **'🚀 تشغيل محاكاة فورية'** من القائمة الجانبية أو قم برفع ملف CSV للتحليل.")