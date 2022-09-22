const express = require("express");
const bodyParser = require("body-parser");

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

app.listen(port, "0.0.0.0", async () => {
  console.log(`server is running on http://localhost:${port}`);
});
