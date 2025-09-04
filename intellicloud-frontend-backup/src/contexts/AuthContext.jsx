import React, { createContext, useContext } from "react";

const mockUser = {
    email: "admin@intellicloud.com",
    role:  "admin",
};

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    return (
        <AuthContext.Provider value={mockUser}>
            children
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);