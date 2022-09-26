require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const Auth = require("./auth");

const auth = new Auth(
  process.env.AWS_ACCESS_KEY_ID,
  process.env.AWS_SECRET_ACCESS_KEY,
  process.env.POOL_ID,
  process.env.CLIENT_ID,
  process.env.REGION,
  process.env.TOKEN_EXPIRATION
);

const app = express();
app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: false }));

let port = process.env.PORT || 3000;

app.get("/", (req, res) => {
  return res.send("auth v1.0");
});

app.post("/auth/signup", async (req, res) => {
  const user = req.body;

  try {
    const result = await auth.signUpUser(user);
    // result is UserSub and represending user id in cognito

    return res.status(200).end();
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/signup/admin", async (req, res) => {
  const user = req.body;

  try {
    const result = await auth.signUpAdmin(user);
    // result is UserSub and represending user id in cognito

    return res.status(200).end();
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/confirmSignUp", async (req, res) => {
  try {
    const user = req.body;
    const result = await auth.confirmSignUp(user.email, user.otp);

    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/login", async (req, res) => {
  const user = req.body;
  try {
    const result = await auth.login(user);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/logout", async (req, res) => {
  let accessTokenFromClient = req.headers["Authorization"] || req.headers["authorization"];
  if (!accessTokenFromClient) return res.status(401).send("Access Token missing from header");

  accessTokenFromClient = accessTokenFromClient.replace("Bearer ", "");

  try {
    const result = await auth.logout(accessTokenFromClient);
    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/toggle-mfa", async (req, res) => {
  let accessTokenFromClient = req.headers["Authorization"] || req.headers["authorization"];
  if (!accessTokenFromClient) return res.status(401).send("Access Token missing from header");

  accessTokenFromClient = accessTokenFromClient.replace("Bearer ", "");

  try {
    const result = await auth.toggleMFA(accessTokenFromClient, true);
    console.log(result);
    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/forgot-password", async (req, res) => {
  try {
    const result = await auth.forgotPassword(req.body.email);
    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/confirm-forgot-password", async (req, res) => {
  try {
    const { email, code, password } = req.body;
    const result = await auth.confirmForgotPassword(email, code, password);
    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.post("/auth/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const result = await auth.refreshToken(refreshToken);
    return res.json(result);
  } catch (error) {
    return res.status(400).json(error);
  }
});

app.get("/admin-only", auth.adminOnly, async (req, res) => {
  res.status(200).send("Admin access");
});

app.get("/user-only", auth.userOnly, async (req, res) => {
  res.status(200).send("User access");
});

app.listen(port, "0.0.0.0", async () => {
  console.log(`server is running on http://localhost:${port}`);
});
