import type { VercelRequest, VercelResponse } from "@vercel/node";
import admin from "../lib/firebase-admin";

type Role = "admin" | "sub_admin" | "user";

const DEFAULT_PERMISSIONS = {
  admin: {
    dashboard: true,
    reports: true,
    inventory: true,
    orders: true,
    customers: true,
    settings: true,
  },
  sub_admin: {
    dashboard: true,
    reports: false,
    inventory: false,
    orders: false,
    customers: false,
    settings: false,
  },
  cashier: {
    dashboard: true,
    reports: false,
    inventory: false,
    orders: true,
    customers: true,
    settings: false,
  },
  user: {
    dashboard: false,
    reports: false,
    inventory: false,
    orders: false,
    customers: false,
    settings: false,
  },
};

/**
 * Set Role API
 * Assigns a role to a user (admin only)
 *
 * POST /api/set-role
 * Headers: Authorization: Bearer <admin-id-token>
 * Body: { "uid": "target-user-uid", "role": "admin" | "sub_admin" | "user" }
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Verify admin token
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing authorization header" });
  }

  const idToken = authHeader.split("Bearer ")[1];

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Only admins can set roles
    if (decodedToken.role !== "admin") {
      return res.status(403).json({ error: "Forbidden. Admin only." });
    }

    const { uid, role } = req.body;

    if (!uid || !role) {
      return res.status(400).json({ error: "uid and role are required" });
    }

    if (!["admin", "sub_admin", "user", "cashier"].includes(role)) {
      return res
        .status(400)
        .json({ error: "Invalid role. Use: admin, sub_admin, user" });
    }

    const permissions = DEFAULT_PERMISSIONS[role as Role];

    // Set custom claims (Role + Permissions)
    await admin.auth().setCustomUserClaims(uid, { role, permissions });

    // Update or create Firestore user document
    const userRef = admin.firestore().collection("users").doc(uid);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      await userRef.update({ role, permissions });
    } else {
      await userRef.set({
        role,
        permissions,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    res.status(200).json({
      success: true,
      message: `Role "${role}" assigned to user ${uid}`,
    });
  } catch (error: any) {
    console.error("Set role error:", error);
    res.status(500).json({
      error: "Failed to set role",
      message: error.message,
    });
  }
}
