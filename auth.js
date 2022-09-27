const CognitoExpress = require("cognito-express");
const AWS = require("aws-sdk");
const crypto = require("crypto");

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
        tokenExpiration: this.expiration * 1000,
      });
    }
  }

  get poolData() {
    return {
      UserPoolId: this.poolId,
      ClientId: this.clientId,
    };
  }

  getUserInfo = async (accessToken) => {
    const info = await this.cognitoExpress.validate(accessToken);
    return {
      username: info.username,
      sub: info.sub,
      groups: info["cognito:groups"],
    };
  };

  auth = (req) => {
    let accessTokenFromClient = req.headers["Authorization"] || req.headers["authorization"];
    if (!accessTokenFromClient) return res.status(401).send("Access Token missing from header");

    accessTokenFromClient = accessTokenFromClient.replace("Bearer ", "");
    return this.cognitoExpress.validate(accessTokenFromClient);
  };

  adminOnly = async (req, res, next) => {
    try {
      const response = await this.auth(req);

      const groups = response["cognito:groups"];
      if (!(groups || []).includes(Groups.admin)) {
        return res.status(401).send({ name: "AuthError", message: "Only Admin can access" });
      }

      req.user = {
        username: response.username,
        sub: response.sub,
        groups,
      };

      next();
    } catch (error) {
      return res.status(401).send(error);
    }
  };

  userOnly = async (req, res, next) => {
    try {
      const response = await this.auth(req);

      const groups = response["cognito:groups"];
      if (!((groups || []).includes(Groups.admin) || (groups || []).includes(Groups.user))) {
        return res.status(401).send({ name: "AuthError", message: "Only users can access" });
      }

      req.user = {
        username: response.username,
        sub: response.sub,
        groups,
      };

      next();
    } catch (error) {
      return res.status(401).send(error);
    }
  };

  generateHash(username) {
    return crypto
      .createHmac("SHA256", this.clientSecret)
      .update(username + this.clientId)
      .digest("base64");
  }
}

Auth.prototype._signUp = async function (user) {
  const params = {
    ClientId: this.clientId,
    Password: user.password,
    Username: user.username,
    UserAttributes: [
      { Name: "email", Value: user.email },
      { Name: "phone_number", Value: user.phone },
    ],
  };

  return await this.cognitoIdentity.signUp(params).promise();
};

Auth.prototype.signUpAdmin = async function (user) {
  const res = await this._signUp(user);

  const params = {
    GroupName: Groups.admin,
    UserPoolId: this.poolId,
    Username: user.username,
  };

  await this.cognitoIdentity.adminAddUserToGroup(params).promise();

  return res;
};

Auth.prototype.autoVerify = async function (user) {
  const confirmParams = {
    Username: user.username,
    UserPoolId: this.poolId,
  }

  await this.cognitoIdentity.adminConfirmSignUp(confirmParams).promise();

  const params = {
    Username: user.username,
    UserPoolId: this.poolId,
    UserAttributes: [],
  };

  if (user.email) {
    params.UserAttributes.push({ Name: "email_verified", Value: "true" });
  }

  if (user.phone) {
    params.UserAttributes.push({ Name: "phone_number_verified", Value: "true" });
  }

  console.log(params);

  return await this.cognitoIdentity.adminUpdateUserAttributes(params).promise();
};

Auth.prototype.signUpUser = async function (user) {
  const res = await this._signUp(user);

  const params = {
    GroupName: Groups.user,
    UserPoolId: this.poolId,
    Username: user.username,
  };

  await this.cognitoIdentity.adminAddUserToGroup(params).promise();

  return res;
};

Auth.prototype.confirmSignUp = async function (username, otp) {
  const params = {
    ClientId: this.clientId,
    ConfirmationCode: otp,
    Username: username,
  };

  return await this.cognitoIdentity.confirmSignUp(params).promise();
};

Auth.prototype.login = async function (user) {
  const payload = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: this.clientId,
    AuthParameters: {
      USERNAME: user.username,
      PASSWORD: user.password,
    },
  };

  return await this.cognitoIdentity.initiateAuth(payload).promise();
};

Auth.prototype.logout = async function (token) {
  const params = {
    AccessToken: token,
  };

  return await this.cognitoIdentity.globalSignOut(params).promise();
};

Auth.prototype.toggleMFA = async function (accessToken, on) {
  /**
   * on = true/false
   */
  const params = {
    AccessToken: accessToken,
    SMSMfaSettings: {
      Enabled: on,
      PreferredMfa: on,
    },
    SoftwareTokenMfaSettings: {
      Enabled: false,
      PreferredMfa: false,
    },
  };

  return await this.cognitoIdentity.setUserMFAPreference(params).promise();
};

Auth.prototype.forgotPassword = async function (username) {
  const params = {
    ClientId: this.clientId,
    Username: username,
  };

  return await this.cognitoIdentity.forgotPassword(params).promise();
};

Auth.prototype.confirmForgotPassword = async function (username, confirmCode, password) {
  const params = {
    ClientId: this.clientId,
    ConfirmationCode: confirmCode,
    Password: password,
    Username: username,
  };
  return await this.cognitoIdentity.confirmForgotPassword(params).promise();
};

Auth.prototype.refreshToken = async function (refreshToken) {
  const payload = {
    AuthFlow: "REFRESH_TOKEN_AUTH",
    ClientId: this.clientId,
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
    },
  };

  return await this.cognitoIdentity.initiateAuth(payload).promise();
};
module.exports = Auth;
