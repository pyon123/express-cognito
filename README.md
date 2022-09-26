# Cognito Auth with Express

## Setup Cognito

This guid assumes that you are working on the old dashboard. (See 01 ~ 11.png in assets)

1. Go to cognito console in AWS and click `"Manage User Pools"`.
2. Click `"Create a user pool"`.
3. Step 1 (Name): Add pool name and choose "Step through settings".
4. Step 2 (Attributes): Select `"Allow both email addresses and phone numbers (users can choose one)"` option under `"Email addresss or phone number"`, choose `email` and `phone number` as required Attributes and click `Next step`.
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

---

## IAM
To create user group or add a user into a specific user group, you need `AmazonCognitoPowerUser` IAM role and set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`  when you ceate auth instance. (see 12.png)

---

## API usage
