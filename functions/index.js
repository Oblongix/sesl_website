const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const { getStorage } = require("firebase-admin/storage");

// Initialise only once
if (!admin.apps.length) {
  admin.initializeApp();
}

// Callable function: requires login, returns a short-lived signed URL for the protected binary
exports.getDownloadLink = onCall(async (req) => {
  const user = req.auth?.token;
  if (!user) {
    throw new HttpsError("unauthenticated", "Login required.");
  }

  // Update the path if you store the file elsewhere in Storage
  const [files] = await getStorage().bucket().getFiles();
  console.log(files.map(f => f.name));

  const file = getStorage().bucket().file("sesl.zip");
  

  // 10-minute signed URL; adjust as needed
  const [url] = await file.getSignedUrl({
    action: "read",
    expires: Date.now() + 10 * 60 * 1000,
    responseDisposition: "attachment; filename=sesl.exe",
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
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match) {
      res.set("Access-Control-Allow-Origin", origin);
      res.status(401).json({ error: "unauthenticated" });
      return;
    }

    const idToken = match[1];
    await admin.auth().verifyIdToken(idToken);

    const file = getStorage().bucket().file("sesl.zip");
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
