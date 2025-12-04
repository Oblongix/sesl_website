// --- Firebase Core Setup ---
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import { 
  getAuth, 
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js";

// TODO: Replace this with your real Firebase project config
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  appId: "YOUR_APP_ID"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// Make available globally
window.auth = auth;
window.signOut = signOut;

// Listen for login/logout
onAuthStateChanged(auth, (user) => {
  const loginBtn = document.getElementById("loginBtn");
  const logoutBtn = document.getElementById("logoutBtn");

  if (user) {
    loginBtn?.classList.add("hidden");
    logoutBtn?.classList.remove("hidden");
  } else {
    logoutBtn?.classList.add("hidden");
    loginBtn?.classList.remove("hidden");
  }
});
