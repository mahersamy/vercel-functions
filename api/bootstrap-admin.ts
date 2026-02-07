import type { VercelRequest, VercelResponse } from "@vercel/node";
import admin from "../lib/firebase-admin";

/**
 * Bootstrap Admin API
 * Creates the FIRST admin user (ONE TIME USE)
 *
 * POST /api/bootstrap-admin
 * Headers: x-bootstrap-secret: YOUR_SECRET
 * Body: { "uid": "firebase-user-uid" }
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, x-bootstrap-secret",
  );

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Verify bootstrap secret
  const secret = req.headers["x-bootstrap-secret"];
  if (secret !== process.env.BOOTSTRAP_ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { uid } = req.body;
  if (!uid) {
    return res.status(400).json({ error: "uid is required" });
  }

  try {
    const permissions = {
      dashboard: true,
      reports: true,
      inventory: true,
      orders: true,
      customers: true,
      settings: true,
    };

    // Set custom claims: role = admin AND permissions
    await admin.auth().setCustomUserClaims(uid, {
      role: "admin",
      permissions,
    });

    // Create Firestore user document with full permissions
    await admin.firestore().collection("users").doc(uid).set({
      role: "admin",
      permissions,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(200).json({
      success: true,
      message: "Admin bootstrapped successfully. DELETE THIS ENDPOINT NOW!",
    });
  } catch (error: any) {
    console.error("Bootstrap error:", error);
    res.status(500).json({
      error: "Bootstrap failed",
      message: error.message,
    });
  }
}
