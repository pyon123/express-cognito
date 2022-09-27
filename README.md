# Cognito Auth with Express

## Setup Cognito

This guid assumes that you are working on the old dashboard. (See 01 ~ 13.png in assets)

1. Go to cognito console in AWS and click `"Manage User Pools"`.
2. Click `"Create a user pool"`.
3. Step 1 (Name): Add pool name and choose "Step through settings".
4. Step 2 (Attributes): Select `"Allow both email addresses and phone numbers (users can choose one)"` option under `"Username"`, choose `email` and `phone number` as required Attributes and click `Next step`.
5. Step 3 (Policies): Go `Next step`.
6. Step 4 (MFA and verifications) \
You can skip this step by clicking `Next step` if you don't want MFA.
- Chose `"Optional"` and check `"SMS text message"` under "Which second factors do you want to enable?".
- Leave as default for the `"How will a user be able to recover their account?"` and `"Which attributes do you want to verify?"`.
- Set up SNS and IAM role.
- Go to `Next step`.
You can enable MFA later.

7. Step 5 (Message customizations): Go `Next step`.
8. Step 6 (Tags): Go `Next step`.
9. Step 7 (Devices): Select No and go next.
10. Step 8 (Add an app client):
- Add `app name`.
- Uncheck `Generate client secret`
- Check `Enable username password based authentication (ALLOW_USER_PASSWORD_AUTH)` under `Auth Flows Configuration`.
- Create app client 
- After creation, you can find the app client Id in App clients page. (see 11.png in assets) \

You can add app client later if you forget to add it in this step.

11. Step 9 (Triggers): Go `Next step`.
12. Step 10 (Review): Create pool.
13. After creation, you can find the `pool id` in General settings page.
14. Create 2 user groups named `"Admin"` and `"User"`.
- Go to `users and groups` page and select `"Groups"` tab.

---

## IAM
To create user group or add a user into a specific user group, you need `AmazonCognitoPowerUser` IAM role and set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`  when you ceate auth instance. (see 14.png)

---

## API usage

### Check api postman examples in the `postman` directory. 

1. Init Auth
```
require("dotenv").config();

const Auth = require("./auth");

const auth = new Auth(
  process.env.AWS_ACCESS_KEY_ID,
  process.env.AWS_SECRET_ACCESS_KEY,
  process.env.POOL_ID,
  process.env.CLIENT_ID,
  process.env.REGION,
  process.env.TOKEN_EXPIRATION
);

- AWS_ACCESS_KEY_ID: AWS_ACCESS_KEY_ID which has AmazonCognitoPowerUser IAM role
- AWS_SECRET_ACCESS_KEY: AWS_SECRET_ACCESS_KEY which has AmazonCognitoPowerUser IAM role
- POOL_ID: Cognito User Pool Id
- CLIENT_ID: Cognito app client id which is created in the user pool.
- REGION: AWS REGION where the user pool is created.
- TOKEN_EXPIRATION: token expiration seconds (number)
```

2. Signup

Sign up function for `User` user group.

```
const result = await auth.signUpUser(user);

user is a json object. required fields:
{
    "username": String,
    "email": String,
    "password": String,
    "phone": String (required country code and "+" prefix)
}
```

3. SignupAdmin

Sign up function for `Admin` user group.

```
const result = await auth.signUpAdmin(user);

user is a json object. required fields:
{
    "username": String
    "email": String,
    "password": String,
    "phone": String (required country code and "+" prefix)
}
```

4. Confirm Signup

Confirm signup with otp which is sent to the provided email.

```
const { username, otp } = req.body;
const result = await auth.confirmSignUp(username, otp);
```

5. Login
```
const result = await auth.login(user);
{
    "username": String,
    "password": String,
}
```

6. logout
```
let accessTokenFromClient = req.headers["Authorization"] || req.headers["authorization"];
accessTokenFromClient = accessTokenFromClient.replace("Bearer ", "");

const result = await auth.logout(accessTokenFromClient);
```

7. Forgot password
```
const result = await auth.forgotPassword(req.body.username);
```

8. Confirm forgot password
```
const { username, code, password } = req.body;
const result = await auth.confirmForgotPassword(username, code, password);
```

9. Refresh token
for token refresh.
```
const { refreshToken } = req.body;
const result = await auth.refreshToken(refreshToken);
```

10. Admin only auth middleware
```
app.get("/admin-only", auth.adminOnly, async (req, res) => {
  console.log(req.user);
  res.status(200).send("Admin access");
});
```
middleware will return user in request.

11. User only auth middleware
```
app.get("/user-only", auth.userOnly, async (req, res) => {
  console.log(req.user);
  res.status(200).send("User access");
});
```
middleware will return user in request.

12. userOptional auth middleware
Not preventing endpoint, gut it checks user logged in based on Authorization header and if exists, it adds user data in req.user, if not, it adds false in req.user.
```
app.get("/users/optional", auth.userOptional, async (req, res) => {
  res.json(req.user ? req.user : {});
});
```

13. getUserInfo
Get user info from access token.
```
const userInfo = await auth.getUserInfo(accessToken);
```