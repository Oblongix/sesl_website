// --- Firebase Core Setup ---
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js";

// TODO: Replace this with your real Firebase project config
const firebaseConfig = {
  apiKey: "AIzaSyDl6a4QfGH8LdcvA4QOYGtTSHEG1zr35yM",
  authDomain: "sesl-website-98721997-dd76a.firebaseapp.com",
  projectId: "sesl-website-98721997-dd76a",
  storageBucket: "sesl-website-98721997-dd76a.firebasestorage.app",
  messagingSenderId: "674237923200",
  appId: "1:674237923200:web:661fe0f3e1569663c88b65"
};
// Initialize Firebase
const app = initializeApp(firebaseConfig);
// Export so other modules can import the singleton auth instance
export const auth = getAuth(app);
export const firebaseSignOut = signOut;

// Make available globally for any legacy inline scripts
window.auth = auth;
window.signOut = signOut;

// Listen for login/logout
onAuthStateChanged(auth, (user) => {
  const loginEls = document.querySelectorAll("#loginBtn, [data-auth=login]");
  const logoutEls = document.querySelectorAll("#logoutBtn, [data-auth=logout]");
  const authed = !!user;

  loginEls.forEach((el) => {
    authed ? el.classList.add("hidden") : el.classList.remove("hidden");
  });
  logoutEls.forEach((el) => {
    authed ? el.classList.remove("hidden") : el.classList.add("hidden");
  });

  document.body.classList.toggle("authed", authed);
});
