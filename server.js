
const http = require("http");
const crypto = require("crypto");

const APP_ID = 1241590671;
const SERVER_SECRET = process.env.ZEGO_SERVER_SECRET;
const PORT = process.env.PORT || 3000;

function generateToken04(userId) {
  if (!SERVER_SECRET || Buffer.byteLength(SERVER_SECRET) !== 32) {
    throw new Error("ZEGO_SERVER_SECRET must be set to the 32-byte ServerSecret");
  }

  const now = Math.floor(Date.now() / 1000);
  const expire = now + 3600;

  const tokenInfo = {
    app_id: APP_ID,
    user_id: userId,
    nonce: crypto.randomInt(0, 2147483647),
    ctime: now,
    expire: expire,
    payload: ""
  };

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(SERVER_SECRET, "utf8"),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(tokenInfo), "utf8"),
    cipher.final()
  ]);

  const header = Buffer.alloc(10);
  header.writeBigInt64BE(BigInt(expire), 0);
  header.writeUInt16BE(iv.length, 8);

  const length = Buffer.alloc(2);
  length.writeUInt16BE(encrypted.length, 0);

  return "04" + Buffer.concat([
    header,
    iv,
    length,
    encrypted
  ]).toString("base64");
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      message: "DilKiMehfil token server is running"
    }));
  }

  if (url.pathname !== "/token" || req.method !== "GET") {
    res.writeHead(404);
    return res.end(JSON.stringify({ error: "Not found" }));
  }

  const userId = url.searchParams.get("userId");

  if (!userId || !/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      error: "A valid userId is required"
    }));
  }

  try {
    const token = generateToken04(userId);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ token }));
  } catch (error) {
    console.error(error.message);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Token generation failed" }));
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`DilKiMehfil token server listening on ${PORT}`);
});
