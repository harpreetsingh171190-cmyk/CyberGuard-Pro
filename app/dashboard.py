import os, io
import pandas as pd
import plotly.express as px
import streamlit as st
from app.core import authorize, score_urls, active_version, history
from app.reports import create_pdf
st.set_page_config(page_title='CyberGuard',page_icon='🛡️',layout='wide')
st.title('🛡️ CyberGuard — Security Analysis')
st.caption('Lexical URL scores only; never a guarantee of safety. No URL content is downloaded.')
key=st.text_input('API access token',type='password')
if not authorize(key):
    st.info('Enter the configured CYBERGUARD_API_TOKEN to continue.')
    st.stop()
try:st.success('Active model: '+active_version())
except FileNotFoundError:st.warning('No registered model. Follow README registration instructions.')
text=st.text_area('URLs (one per line)',height=140)
file=st.file_uploader('Or upload a CSV with a url column',type=['csv'])
urls=[x.strip() for x in text.splitlines() if x.strip()]
if file is not None:
    if file.size>2_000_000:st.error('CSV limit: 2 MB');st.stop()
    frame=pd.read_csv(file)
    if 'url' not in frame.columns:st.error('CSV must contain url column');st.stop()
    urls += frame['url'].dropna().astype(str).tolist()
if st.button('Scan',type='primary'):
    if not urls:st.warning('Add URLs first')
    elif len(urls)>500:st.error('Limit: 500 URLs per batch')
    else:
        try:st.session_state['results']=score_urls(urls)
        except Exception as exc:st.error(str(exc))
if st.session_state.get('results'):
    results=st.session_state['results']
    df=pd.DataFrame(results)
    st.dataframe(df,use_container_width=True)
    st.plotly_chart(px.histogram(df,x='risk_score',nbins=20,title='Model score distribution'),use_container_width=True)
    st.plotly_chart(px.pie(df,names='risk_band',title='Risk bands'),use_container_width=True)
    st.download_button('Download CSV',df.to_csv(index=False).encode(),'cyberguard_scans.csv','text/csv')
    st.download_button('Download PDF',create_pdf(results),'cyberguard_report.pdf','application/pdf')
with st.expander('Audit events (no raw scanned URLs stored)'):
    st.dataframe(pd.DataFrame(history(50)),use_container_width=True)
