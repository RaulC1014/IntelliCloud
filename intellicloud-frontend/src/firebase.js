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

const app = initializeApp({
  apiKey: firebaseEnv.apiKey,
  authDomain: firebaseEnv.authDomain,
  projectId: firebaseEnv.projectId,
  appId: firebaseEnv.appId,
});

const auth = getAuth(app);

const register = async (email, password, first, last, dob) => {
  const cred = await createUserWithEmailAndPassword(auth, email, password);
  const user = cred.user;
  const fullName = (first && last) ? `${first} ${last}` : null;
  if (fullName) {
    await updateProfile(user, { displayName: fullName });
    await user.reload();
  }
  return auth.currentUser ?? user;
};

const login = async (email, password) => {
  const cred = await signInWithEmailAndPassword(auth, email, password);
  return cred.user;
};

const logout = () => signOut(auth);

const getCurrentUser = () => auth.currentUser;

const onAuthStateChangedSub = (cb) => onAuthStateChanged(auth, cb);

const isMockAuth = false;

export { app, register, login, logout, getCurrentUser, onAuthStateChangedSub, isMockAuth };
