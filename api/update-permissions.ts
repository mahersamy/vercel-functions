import type { VercelRequest, VercelResponse } from "@vercel/node";
import admin from "../lib/firebase-admin";

type Permissions = {
  dashboard: boolean;
  reports: boolean;
  inventory: boolean;
  orders: boolean;
  customers: boolean;
  settings: boolean;
};

/**
 * Update Permissions API
 * Toggles user permissions (admin only)
 *
 * POST /api/update-permissions
 * Headers: Authorization: Bearer <admin-id-token>
 * Body: {
 *   "uid": "target-user-uid",
 *   "permissions": { "dashboard": true, "reports": false, ... }
 * }
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

    // Only admins can update permissions
    if (decodedToken.role !== "admin") {
      return res.status(403).json({ error: "Forbidden. Admin only." });
    }

    const { uid, permissions } = req.body as {
      uid: string;
      permissions: Partial<Permissions>;
    };

    if (!uid || !permissions) {
      return res
        .status(400)
        .json({ error: "uid and permissions are required" });
    }

    // Validate permissions object
    const validKeys = [
      "dashboard",
      "reports",
      "inventory",
      "orders",
      "customers",
      "settings",
    ];
    const invalidKeys = Object.keys(permissions).filter(
      (k) => !validKeys.includes(k),
    );
    if (invalidKeys.length > 0) {
      return res
        .status(400)
        .json({ error: `Invalid permissions: ${invalidKeys.join(", ")}` });
    }

    // Update Firestore permissions
    const userRef = admin.firestore().collection("users").doc(uid);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found in Firestore" });
    }

    // Merge with existing permissions
    const currentData = userDoc.data();
    const updatedPermissions = {
      ...currentData?.permissions,
      ...permissions,
    };

    await userRef.update({ permissions: updatedPermissions });

    // Sync permissions to Auth Token Custom Claims
    // We keep the existing role and only update the permissions
    await admin.auth().setCustomUserClaims(uid, {
      role: currentData?.role,
      permissions: updatedPermissions,
    });

    res.status(200).json({
      success: true,
      message: "Permissions updated and synced to token",
      permissions: updatedPermissions,
    });
  } catch (error: any) {
    console.error("Update permissions error:", error);
    res.status(500).json({
      error: "Failed to update permissions",
      message: error.message,
    });
  }
}
