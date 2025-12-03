export const USE_MOCK = (import.meta.env.VITE_USE_MOCK ?? 'true') === 'true';
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';

export const firebaseEnv = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

export const isFirebaseConfigured =
  !!(firebaseEnv.apiKey && firebaseEnv.authDomain && firebaseEnv.projectId && firebaseEnv.appId);
