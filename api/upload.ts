import type { VercelRequest, VercelResponse } from "@vercel/node";
import { v2 as cloudinary } from "cloudinary";
import formidable from "formidable";

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Disable body parsing, we'll handle it with formidable
export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS Headers
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,OPTIONS,PATCH,DELETE,POST,PUT",
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version",
  );

  // Handle preflight OPTIONS request
  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  // Only allow POST
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed. Use POST." });
    return;
  }

  try {
    // Parse the multipart form data
    const form = formidable({});
    const [fields, files] = await form.parse(req as any);

    // Get the uploaded file
    const fileArray = files.file;
    if (!fileArray || fileArray.length === 0) {
      res
        .status(400)
        .json({ error: 'No file uploaded. Use key "file" in form-data.' });
      return;
    }

    const file = fileArray[0];

    // Upload to Cloudinary using upload_stream
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "uploads", // Optional: organize in a folder
          resource_type: "auto", // Auto-detect file type
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        },
      );

      // Read file and pipe to Cloudinary
      const fs = require("fs");
      const fileStream = fs.createReadStream(file.filepath);
      fileStream.pipe(uploadStream);
    });

    // Return the Cloudinary URL
    res.status(200).json({
      success: true,
      url: (uploadResult as any).secure_url,
      publicId: (uploadResult as any).public_id,
    });
  } catch (error: any) {
    console.error("Upload error:", error);
    res.status(500).json({
      error: "Upload failed",
      message: error.message,
    });
  }
}
