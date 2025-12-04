import { 
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail
} from "https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js";

// Modal elements
const authModal = document.getElementById("authModal");
const authClose = document.getElementById("authClose");

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const resetForm = document.getElementById("resetForm");

const authTitle = document.getElementById("authTitle");

// Switchers
document.getElementById("goRegister")?.addEventListener("click", showRegister);
document.getElementById("goLogin1")?.addEventListener("click", showLogin);
document.getElementById("goLogin2")?.addEventListener("click", showLogin);
document.getElementById("goReset")?.addEventListener("click", showReset);

// Open modal from login button
document.getElementById("loginBtn")?.addEventListener("click", () => {
  authModal.classList.remove("hidden");
  authModal.classList.add("flex");
  showLogin();
});

// Close modal
authClose?.addEventListener("click", () => {
  authModal.classList.add("hidden");
  authModal.classList.remove("flex");
});

// --- Form Display Helpers ---
function showLogin() {
  authTitle.textContent = "Login";
  loginForm?.classList.remove("hidden");
  registerForm?.classList.add("hidden");
  resetForm?.classList.add("hidden");
}

function showRegister() {
  authTitle.textContent = "Create Account";
  loginForm?.classList.add("hidden");
  registerForm?.classList.remove("hidden");
  resetForm?.classList.add("hidden");
}

function showReset() {
  authTitle.textContent = "Reset Password";
  loginForm?.classList.add("hidden");
  registerForm?.classList.add("hidden");
  resetForm?.classList.remove("hidden");
}

// --- LOGIN ---
loginForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  try {
    await signInWithEmailAndPassword(auth, email, password);
    closeModal();
    alert("Logged in");
  } catch (err) {
    alert(err.message);
  }
});

// --- REGISTER ---
registerForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("regEmail").value;
  const password = document.getElementById("regPassword").value;

  try {
    await createUserWithEmailAndPassword(auth, email, password);
    closeModal();
    alert("Account created");
  } catch (err) {
    alert(err.message);
  }
});

// --- RESET PASSWORD ---
resetForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("resetEmail").value;

  try {
    await sendPasswordResetEmail(auth, email);
    alert("Password reset email sent.");
    showLogin();
  } catch (err) {
    alert(err.message);
  }
});

// Close modal helper
function closeModal() {
  authModal.classList.add("hidden");
  authModal.classList.remove("flex");
}
