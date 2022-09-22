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

class Auth {
  poolId = "";
  clientId = "";
  clientSecret = "";
  region = "us-east-1";
  expiration = 3600;
  userPool = null;
  cognitoExpress = null;
  cognitoIdentity = null;

  constructor(poolId, clientId, region = "us-east-1", expiration = 3600) {
    this.poolId = poolId;
    this.clientId = clientId;
    this.region = region;
    this.expiration = expiration;

    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider({
      apiVersion: "2016-04-18",
      region: this.region,
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
    const params = {
      ClientId: this.clientId,
      Password: user.password,
      Username: user.email.toLowerCase(),
      UserAttributes: [
        { Name: "email", Value: user.email },
        { Name: "phone_number", Value: user.phone },
      ],
    };

    await this.cognitoIdentity.signUp(params).promise();

    return true;
  } catch (error) {
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
      UserPoolId: this.poolId,
      AuthFlow: "ADMIN_NO_SRP_AUTH",
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: user.email.toLowerCase(),
        PASSWORD: user.password,
      },
    };

    const res = await this.cognitoIdentity.adminInitiateAuth(payload).promise();
    console.log(res);
    return res;
  } catch (error) {
    console.log(error);
    return null;
  }
};

module.exports = Auth;
