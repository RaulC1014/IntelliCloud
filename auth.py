import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth

cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred)

def verify_token(id_token):
    """
    Verifies the firebase ID token from client
    returns the decoded token if valid, none if invalid
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        print("Token verification failed: ", e)
        return None
    