import type { VercelRequest, VercelResponse } from "@vercel/node";
import admin from "../lib/firebase-admin";

type Role = "admin" | "sub_admin" | "user" | "cashier";

const DEFAULT_PERMISSIONS = {
  admin: {
    dashboard: { read: true, write: true },
    reports: { read: true, write: true },
    inventory: { read: true, write: true },
    orders: { read: true, write: true },
    customers: { read: true, write: true },
    settings: { read: true, write: true },
  },
  sub_admin: {
    dashboard: { read: true, write: true },
    reports: { read: false, write: false },
    inventory: { read: false, write: false },
    orders: { read: false, write: false },
    customers: { read: false, write: false },
    settings: { read: false, write: false },
  },
  cashier: {
    dashboard: { read: true, write: false },
    reports: { read: false, write: false },
    inventory: { read: true, write: false }, // Can see stock
    orders: { read: true, write: true }, // Can process orders
    customers: { read: true, write: true }, // Can add customers
    settings: { read: false, write: false },
  },
  user: {
    dashboard: { read: false, write: false },
    reports: { read: false, write: false },
    inventory: { read: false, write: false },
    orders: { read: false, write: false }, // Standard users don't manage orders
    customers: { read: false, write: false },
    settings: { read: false, write: false },
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
