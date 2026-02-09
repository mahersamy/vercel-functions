import type { VercelRequest, VercelResponse } from "@vercel/node";
import admin from "../lib/firebase-admin";

type Permission = { read: boolean; write: boolean };

type Permissions = {
  dashboard: Permission;
  reports: Permission;
  inventory: Permission;
  orders: Permission;
  customers: Permission;
  settings: Permission;
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

    // Validate permissions keys and structure
    const validKeys = [
      "dashboard",
      "reports",
      "inventory",
      "orders",
      "customers",
      "settings",
    ];

    for (const [key, value] of Object.entries(permissions)) {
      if (!validKeys.includes(key)) {
        return res
          .status(400)
          .json({ error: `Invalid permission module: ${key}` });
      }
      // Ensure strict structure { read: boolean, write: boolean }
      // This prevents sending "true" or partial objects that break the schema
      if (
        typeof value !== "object" ||
        typeof value.read !== "boolean" ||
        typeof value.write !== "boolean"
      ) {
        return res.status(400).json({
          error: `Permission '${key}' must be { read: boolean, write: boolean }`,
        });
      }
    }

    // Update Firestore permissions
    const userRef = admin.firestore().collection("users").doc(uid);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found in Firestore" });
    }

    // Merge with existing permissions
    const currentData = userDoc.data();
    const currentPermissions = currentData?.permissions || {};

    // Create the new permissions object by merging
    // Since we validated the input is complete {read, write}, we can overwrite the module key safely
    const updatedPermissions = {
      ...currentPermissions,
      ...permissions,
    };

    await userRef.update({ permissions: updatedPermissions });

    // Sync permissions to Auth Token Custom Claims (The "Pin")
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
