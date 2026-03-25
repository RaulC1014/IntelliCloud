const isElectron = window.location.protocol === 'file:';

// 2. If desktop, turn off mock data so it talks to the real Python backend
export const USE_MOCK = isElectron ? false : (import.meta.env.VITE_USE_MOCK ?? 'true') === 'true';

// 3. If desktop, force the API to point to your local Python server instead of the hard drive
export const API_BASE_URL = isElectron 
  ? 'http://127.0.0.1:5000' 
  : (import.meta.env.VITE_API_BASE_URL || '');

export const VITE_CLIENT_KEY = import.meta.env.VITE_CLIENT_KEY || '';

export const firebaseEnv = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

export const isFirebaseConfigured =
  !!(firebaseEnv.apiKey && firebaseEnv.authDomain && firebaseEnv.projectId && firebaseEnv.appId);