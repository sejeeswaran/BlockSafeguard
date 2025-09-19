import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin import auth

# Initialize Firebase Admin SDK
import logging

def initialize_firebase():
    # Path to your Firebase service account key JSON file
    cred = credentials.Certificate("FIREBASE JSON FILE NAME")
    try:
        firebase_admin.initialize_app(cred)
        logging.info("Firebase app initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize Firebase app: {e}")
    db = firestore.client()
    return db

db = initialize_firebase()

def log_activity(collection_name, data):
    """
    Log activity data to the specified Firestore collection.
    """
    try:
        doc_ref = db.collection(collection_name).document()
        doc_ref.set(data)
        logging.info(f"Logged activity to {collection_name}: {data}")
    except Exception as e:
        logging.error(f"Failed to log activity to {collection_name}: {e}")
def signup_user(email, password, extra_data):
    user = auth.create_user(email=email, password=password)
    uid = user.uid
    db.collection('users').document(uid).set(extra_data)
    return uid
def verify_token(id_token):
    decoded_token = auth.verify_id_token(id_token)
    uid = decoded_token['uid']
    return uid

def get_user_by_email(email):
    """
    Get user data from Firestore by email.
    """
    try:
        # First, get user from Firebase Auth
        user = auth.get_user_by_email(email)
        uid = user.uid
        # Then, get the document from Firestore
        doc_ref = db.collection('users').document(uid)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        else:
            return None
    except Exception as e:
        logging.error(f"Failed to get user by email: {e}")
        return None

def get_notification_settings():
    """
    Get notification settings from the first user with notifications enabled.
    """
    try:
        users_ref = db.collection('users')
        query = users_ref.where('enable_notifications', '==', True).limit(1)
        docs = query.stream()
        for doc in docs:
            user_data = doc.to_dict()
            return {
                'email_user': user_data.get('email'),
                'email_pass': user_data.get('gmail_app_password'),
                'notification_email': user_data.get('notification_email')
            }
        return None
    except Exception as e:
        logging.error(f"Failed to get notification settings: {e}")
        return None
