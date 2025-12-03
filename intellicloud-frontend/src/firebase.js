// src/firebase.js
import { firebaseEnv } from './config';
import { initializeApp } from 'firebase/app';
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  updateProfile,
} from 'firebase/auth';

// 1. Initialize Real Firebase
const app = initializeApp({
  apiKey: firebaseEnv.apiKey,
  authDomain: firebaseEnv.authDomain,
  projectId: firebaseEnv.projectId,
  appId: firebaseEnv.appId,
});

const auth = getAuth(app);

// 2. Real Registration (With Name Saving & Reload)
const register = async (email, password, first, last, dob) => {
  // Create account on Firebase
  const userCredential = await createUserWithEmailAndPassword(auth, email, password);
  const user = userCredential.user;

  // Save the name immediately
  if (first && last) {
    const fullName = `${first} ${last}`;
    await updateProfile(user, { displayName: fullName });
    
    // CRITICAL FIX: Reload user to ensure the Auth listener sees the new name
    await user.reload();
    
    // Force local update on the object reference just in case
    user.displayName = fullName;
  }
  
  return user;
};

// 3. Real Login
const login = (email, password) =>
  signInWithEmailAndPassword(auth, email, password).then((r) => r.user);

// 4. Real Logout
const logout = () => signOut(auth);

// 5. Helpers
const getCurrentUser = () => auth.currentUser;
const onAuthStateChangedSub = (cb) => onAuthStateChanged(auth, cb);

// Flag to tell the UI we are in Real Mode
const isMockAuth = false;

export { register, login, logout, getCurrentUser, onAuthStateChangedSub, isMockAuth };