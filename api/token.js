const crypto = require("crypto");

const APP_ID = 1241590671;

function generateToken04(userId, secret) {
  const now = Math.floor(Date.now() / 1000);
  const expire = now + 3600;

  const info = {
    app_id: APP_ID,
    user_id: userId,
    nonce: crypto.randomInt(0, 2147483647),
    ctime: now,
    expire,
    payload: ""
  };

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(secret, "utf8"),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(info), "utf8"),
    cipher.final()
  ]);

  const header = Buffer.alloc(10);
  header.writeBigInt64BE(BigInt(expire), 0);
  header.writeUInt16BE(iv.length, 8);

  const length = Buffer.alloc(2);
  length.writeUInt16BE(encrypted.length, 0);

  return "04" + Buffer.concat([
    header, iv, length, encrypted
  ]).toString("base64");
}

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const secret = process.env.ZEGO_SERVER_SECRET;
  const userID = req.body && req.body.userID;

  if (!secret || Buffer.byteLength(secret, "utf8") !== 32) {
    return res.status(500).json({
      error: "Server secret configuration error"
    });
  }

  if (
    typeof userID !== "string" ||
    !/^[a-zA-Z0-9_-]{1,64}$/.test(userID)
  ) {
    return res.status(400).json({
      error: "Invalid userID"
    });
  }

  try {
    const token = generateToken04(userID, secret);
    return res.status(200).json({ token });
  } catch (error) {
    return res.status(500).json({
      error: "Token generation failed"
    });
  }
};
