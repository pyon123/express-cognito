require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const Auth = require("./auth");

const auth = new Auth(
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

  const result = await auth.signUp(user);

  if (result) return res.status(200).end();

  res.status(400).end();
});

app.post("/auth/confirmSignUp", async (req, res) => {
  const user = req.body;
  const result = await auth.confirmSignUp(user.email, user.otp);

  if (result) return res.status(200).end();

  res.status(400).end();
});

app.post("/auth/login", async (req, res) => {
  const user = req.body;
  const result = await auth.login(user);

  if (result) return res.status(200).json(result);

  res.status(400).end();
});

app.listen(port, "0.0.0.0", async () => {
  console.log(`server is running on http://localhost:${port}`);
});
