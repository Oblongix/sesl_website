const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onRequest } = require("firebase-functions/v2/https");

let admin;
let getStorage;

function getAdminApp() {
  if (!admin) {
    admin = require("firebase-admin");
  }
  if (!admin.apps.length) {
    admin.initializeApp();
  }
  return admin;
}

function getDefaultBucket() {
  if (!getStorage) {
    ({ getStorage } = require("firebase-admin/storage"));
  }
  getAdminApp();
  return getStorage().bucket();
}

// Callable function: requires login, returns a short-lived signed URL for the protected binary
exports.getDownloadLink = onCall(async (req) => {
  const user = req.auth?.token;
  if (!user) {
    throw new HttpsError("unauthenticated", "Login required.");
  }

  const file = getDefaultBucket().file("sesl.zip");

  // 10-minute signed URL; adjust as needed
  const [url] = await file.getSignedUrl({
    action: "read",
    expires: Date.now() + 10 * 60 * 1000,
    responseDisposition: "attachment; filename=sesl.zip",
  });

  return { url };
});

// HTTP function with CORS enabled; expects Authorization: Bearer <ID_TOKEN>
exports.getDownloadLinkHttp = onRequest({ cors: true }, async (req, res) => {
  const origin = req.headers.origin || "*";

  // Handle preflight quickly
  if (req.method === "OPTIONS") {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.status(204).send("");
    return;
  }

  try {
    const adminApp = getAdminApp();
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match) {
      res.set("Access-Control-Allow-Origin", origin);
      res.status(401).json({ error: "unauthenticated" });
      return;
    }

    const idToken = match[1];
    await adminApp.auth().verifyIdToken(idToken);

    const file = getDefaultBucket().file("sesl.zip");
    const [url] = await file.getSignedUrl({
      action: "read",
      expires: Date.now() + 10 * 60 * 1000,
      responseDisposition: "attachment; filename=sesl.zip",
    });

    res.set("Access-Control-Allow-Origin", origin);
    res.status(200).json({ url });
  } catch (err) {
    console.error("getDownloadLinkHttp error:", err);
    res.set("Access-Control-Allow-Origin", origin);
    res.status(500).json({ error: "internal" });
  }
});
