const admin = require("firebase-admin");
const serviceAccount = require("../serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const uid = "2tXkcvaoJbVBiDyMzQxtrFmMhCN2";

admin.auth().setCustomUserClaims(uid, { role: "admin" }).then(() => {
    console.log("Admin role assigned to user.");
});