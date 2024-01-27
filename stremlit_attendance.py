import streamlit as st
import uuid
import re
import bcrypt
import firebase_admin
from firebase_admin import credentials, db
import datetime
import pandas as pd

# Initialize Firebase Admin SDK


def initialize_firebase():
    # Initialize Firebase
    CERTIFICATE = "ventura-auth-a83af-firebase-adminsdk-w852k-65559d475d.json"
    DATABASE_URL = 'https://ventura-auth-a83af-default-rtdb.asia-southeast1.firebasedatabase.app/'
    cred = credentials.Certificate(CERTIFICATE)
    firebase_admin.initialize_app(cred, {
        'databaseURL': DATABASE_URL
    })


@st.cache_data
def conver_df(df):
    return df.to_csv().encode('utf-8')


if not firebase_admin._apps:
    initialize_firebase()

# Function to clean email for Firebase path


def clean_email(email):
    return re.sub(r'[^a-zA-Z0-9_]', '_', email)


def get_attendance_data(enterprise_id, filter_year, filter_month, filter_day):
    ref = db.reference(f'/enterprises/{enterprise_id}/attendance/')
    enterprise_data = ref.get()

    if enterprise_data is None:
        st.error("No Enterprise Found")
        return None

    filtered_data = []

    for year, year_data in enterprise_data.items():
        if year != filter_year and filter_year != 'All':
            continue

        for month, month_data in year_data.items():
            if month.lower() != filter_month.lower() and filter_month != 'All':
                continue

            if filter_day != 'All' and filter_day.capitalize() not in month_data.keys():
                continue

            day_data = month_data.get(filter_day.capitalize(), {})

            for name, records in day_data.items():
                if isinstance(records, dict):
                    clock_in_record = list(records.values())[0]
                    clock_out_record = list(records.values())[-1]
                    filtered_data.append(clock_in_record)
                    filtered_data.append(clock_out_record)

    return filtered_data

        
def split_date_time(df):
    df['Date'] = df['date'].str.split(' ').str[0]
    df['Time'] = df['date'].str.split(' ').str[1]
    df.drop(columns=['date'], inplace=True)
    return df

# Streamlit App
def enterprise_login():
    st.title("Ventura Attendance Viewer 💻")

    # Input fields
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    cleaned_email = clean_email(email)

    enterprise_ref = db.reference(f"/enterprises/{cleaned_email}")
    enterprise_info = enterprise_ref.get()

    if not enterprise_info:
        st.error("Invalid Email")
        return

    # Extract hashed password from the stored details
    stored_password = enterprise_info.get('password', '')

    # Check if the entered password matches the stored hashed password
    if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        ref = db.reference(f'/enterprises/{cleaned_email}/attendance/')
        attendance_data = ref.get()
        if attendance_data is not None:
            years = sorted(list(attendance_data.keys()))
            months = sorted(list(set(month.lower()
                            for year in attendance_data.values() for month in year.keys())))
            days = sorted(list(set(day for year in attendance_data.values()
                        for month in year.values() for day in month.keys())))
        else:
            years = []
            months = []
            days = []

        # Display filters
        filter_year = st.selectbox('Filter by Year', ['All'] + years)
        if filter_year != 'All':
            ref = db.reference(f'enterprises/{cleaned_email}/attendance/{filter_year}')
            year_data = ref.get()
            if year_data is not None:
                months = sorted(list(year_data.keys()))
            else:
                months = []
            filter_month = st.selectbox('Filter by Month', ['All'] + months)
        else:
            filter_month = 'All'

        if filter_month != 'All':
            ref = db.reference(
                f'enterprises/{cleaned_email}/attendance/{filter_year}/{filter_month.capitalize()}')
            month_data = ref.get()
            if month_data is not None:
                days = sorted(list(month_data.keys()))
            else:
                days = []
            filter_day = st.selectbox('Filter by Day', ['All'] + days)
        else:
            filter_day = 'All'

        if st.button('Get Attendance ☁️'):
            attendance_data = get_attendance_data(cleaned_email,
                filter_year, filter_month, filter_day)
            if attendance_data is None or len(attendance_data) == 0:
                st.info('No attendance records found.')
            else:
                print("Raw Attendance data", attendance_data)

                df = pd.DataFrame(attendance_data)
                print("DataFrame: ")
                print(df)


                df = split_date_time(df)
                print("DataFrame after splitting data and time: ")
                print(df)

                st.dataframe(df)

                # Get the date of the attendance record
                if filter_day == 'All':
                    date_str = 'All'
                else:
                    date_str = datetime.datetime.strptime(
                        f"{filter_month} {filter_day}, {filter_year}", "%B %d, %Y").strftime("%Y-%m-%d")

                # Create a button to download the filtered data as a CSV file with an icon
                # csv = df.to_csv(index=False)
                # b64 = base64.b64encode(csv.encode()).decode()
                csv = conver_df(df)
                st.download_button(label='⬇️ Download CSV',
                                data=csv,
                                file_name=f"attendance_{date_str}.csv",
                                mime="text/csv")


if __name__ == '__main__':
    enterprise_login()
