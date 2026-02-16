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

function getLoginName(user) {
  if (!user) return "";

  if (user.displayName && user.displayName.trim()) {
    return user.displayName.trim();
  }

  const email = user.email ? user.email.trim() : "";
  if (!email) return "Account";

  const atIndex = email.indexOf("@");
  return atIndex > 0 ? email.slice(0, atIndex) : email;
}

function getOrCreateNameBadge(logoutEl) {
  const parent = logoutEl?.parentElement;
  if (!parent) return null;

  let badge = parent.querySelector("[data-auth='username']");
  if (!badge) {
    badge = document.createElement("span");
    badge.setAttribute("data-auth", "username");
    badge.className = "hidden text-sm text-slate-700 dark:text-slate-200";
    logoutEl.insertAdjacentElement("beforebegin", badge);
  }
  return badge;
}

// Listen for login/logout
onAuthStateChanged(auth, (user) => {
  const loginEls = document.querySelectorAll("#loginBtn, [data-auth=login]");
  const logoutEls = document.querySelectorAll("#logoutBtn, [data-auth=logout]");
  const authed = !!user;
  const loginName = getLoginName(user);

  loginEls.forEach((el) => {
    authed ? el.classList.add("hidden") : el.classList.remove("hidden");
  });
  logoutEls.forEach((el) => {
    authed ? el.classList.remove("hidden") : el.classList.add("hidden");

    const badge = getOrCreateNameBadge(el);
    if (!badge) return;

    if (authed) {
      badge.textContent = loginName;
      badge.classList.remove("hidden");
    } else {
      badge.textContent = "";
      badge.classList.add("hidden");
    }
  });

  document.body.classList.toggle("authed", authed);
});
