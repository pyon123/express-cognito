const CognitoExpress = require("cognito-express");
const AWS = require("aws-sdk");
const crypto = require("crypto");

// const authenticatedRoute = (req, res, next) => {
//   let accessTokenFromClient = req.headers.accesstoken;
//   if (!accessTokenFromClient)
//     return res.status(401).send("Access Token missing from header");
//   cognitoExpress.validate(accessTokenFromClient, (err, response) => {
//     if (err) return res.status(401).send(err);
//     res.locals.user = response;
//     next();
//   });
// };

const Groups = {
  admin: "Admin",
  user: "User",
};

class Auth {
  accessKeyId = "";
  secretAccessKey = "";
  poolId = "";
  clientId = "";
  clientSecret = "";
  region = "us-east-1";
  expiration = 3600;

  cognitoExpress = null;
  cognitoIdentity = null;

  constructor(accessKeyId, secretAccessKey, poolId, clientId, region = "us-east-1", expiration = 3600) {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.poolId = poolId;
    this.clientId = clientId;
    this.region = region;
    this.expiration = expiration;

    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider({
      apiVersion: "2016-04-18",
      region: this.region,
      credentials: {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      },
    });

    if (poolId && clientId) {
      this.cognitoExpress = new CognitoExpress({
        region: this.region,
        cognitoUserPoolId: this.poolId,
        tokenUse: "access",
        tokenExpiration: this.expiration,
      });
    }
  }

  get poolData() {
    return {
      UserPoolId: this.poolId,
      ClientId: this.clientId,
    };
  }

  generateHash(username) {
    return crypto
      .createHmac("SHA256", this.clientSecret)
      .update(username + this.clientId)
      .digest("base64");
  }
}

Auth.prototype.signUp = async function (user) {
  try {
    const email = user.email.toLowerCase();
    const params = {
      ClientId: this.clientId,
      Password: user.password,
      Username: email,
      UserAttributes: [
        { Name: "email", Value: email },
        { Name: "phone_number", Value: user.phone },
      ],
    };

    await this.cognitoIdentity.signUp(params).promise();

    return true;
  } catch (error) {
    return false;
  }
};

Auth.prototype.signUpAdmin = async function (user) {
  try {
    await this.signUp(user);

    const params = {
      GroupName: Groups.admin,
      UserPoolId: this.poolId,
      Username: user.email.toLowerCase(),
    };

    await this.cognitoIdentity.adminAddUserToGroup(params).promise();

    return true;
  } catch (error) {
    console.log(error);
    return false;
  }
};

Auth.prototype.signUpUser = async function (user) {
  try {
    await this.signUp(user);

    const params = {
      GroupName: Groups.user,
      UserPoolId: this.poolId,
      Username: user.email.toLowerCase(),
    };

    await this.cognitoIdentity.adminAddUserToGroup(params).promise();

    return true;
  } catch (error) {
    console.log(error);
    return false;
  }
};

Auth.prototype.confirmSignUp = async function (email, otp) {
  try {
    const params = {
      ClientId: this.clientId,
      ConfirmationCode: otp,
      Username: email.toLowerCase(),
    };

    await this.cognitoIdentity.confirmSignUp(params).promise();

    return true;
  } catch (error) {
    return false;
  }
};

Auth.prototype.login = async function (user) {
  try {
    const payload = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: user.email.toLowerCase(),
        PASSWORD: user.password,
      },
    };

    const res = await this.cognitoIdentity.initiateAuth(payload).promise();

    return res;
  } catch (error) {
    return null;
  }
};

module.exports = Auth;
