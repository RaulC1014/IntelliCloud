import React, { useState, useEffect } from "react";
import { auth } from "../firebase";
import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  onAuthStateChanged 
} from "firebase/auth";

export default function AuthTest() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSignup = async() => {
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      alert("User created: " + userCredential.user.email);
    } catch (error) {
      alert("Error: " + error.message);
    }
  };

  const handleLogin = async () => {
    try {
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      alert("Logged in: " + userCredential.user.email);
    } catch (error) {
      alert("Error: " + error.message);
    }
  };

  useEffect (() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
        if (user) {
            console.log("Logged in as: ", user.email);
        } else {
            console.log("Logged out");
        }
    });

    return () => unsubscribe();
  }, []);
    
  return (
    <div>
      <h2>Auth Test</h2>
      <input type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)} placeholder="Email"/>
      <input type="password" 
        value={password} 
        onChange={(e) => setPassword(e.target.value)} placeholder="Password"/>
      <div style={{ marginTop: "10px" }}>
        <button onClick={handleSignup}> Sign Up </button>
        <button onClick={handleLogin} style ={{marginLeft: "10px" }}>Login</button>
      </div>
    </div>
  );
}
