const CognitoExpress = require("cognito-express");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const AWS = require("aws-sdk");
// global.fetch = require("node-fetch");

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
  cognitoIdentityServiceProvider = null;

  constructor(poolId, clientId, clientSecret, region = "us-east-1", expiration = 3600) {
    this.poolId = poolId;
    this.clientId = clientId;
		this.clientSecret =  clientSecret;
    this.region = region;
    this.expiration = expiration;

    if (poolId && clientId) {
      this.userPool = new AmazonCognitoIdentity.CognitoUserPool(this.poolData);
      this.cognitoExpress = new CognitoExpress({
        region: this.region,
        cognitoUserPoolId: this.poolId,
        tokenUse: "access",
        tokenExpiration: this.expiration,
      });
      this.cognitoIdentityServiceProvider =
        new AWS.CognitoIdentityServiceProvider();
    }
  }

  get poolData() {
    return {
      UserPoolId: this.poolId,
      ClientId: this.clientId,
    };
  }
}

Auth.prototype.signUp = async function (user) {
  try {
    user.email = user.email.toLowerCase();
    let attributeList = [];
    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "name",
        Value: user.userName || "",
      })
    );
    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "email",
        Value: user.email || "",
      })
    );
    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "phone_number",
        Value: user.phoneNumber || "",
      })
    );

    console.log(attributeList);

    console.log(this.poolData);

    const cognitoUser = await new Promise((resolve) => {
      this.userPool.signUp(
        user.email,
        user.password,
        attributeList,
        null,
        (err, result) => {
          if (err) resolve(err);
          else resolve(result);
        }
      );
    });
    console.log("===>", cognitoUser);
    return {};
  } catch (error) {
    throw error;
  }
};

module.exports = Auth;

// const changePassword = async (user) => {
//   cognitoUser = new AmazonCognitoIdentity.CognitoUser({
//     Username: user.email,
//     Pool: userPool,
//   });
//   cognitoUser.forgotPassword({
//     onSuccess: function (result) {
//       return res.status(200).send({
//         status: 200,
//         title: "Verification code sent",
//         ...result,
//       });
//     },
//     onFailure: function (err) {
//       return res.status(400).send({
//         errors: [
//           {
//             status: 400,
//             title: err.message,
//           },
//         ],
//       });
//     },
//   });
// };

// const confirmPassword = async (user) => {
//   cognitoUser = new AmazonCognitoIdentity.CognitoUser({
//     Username: user.email,
//     Pool: userPool,
//   });
//   cognitoUser.confirmPassword(user.otp, user.newPassword, {
//     onSuccess: function (result) {
//       return res.status(200).send({
//         status: 200,
//         title: "Password changed",
//         ...result,
//       });
//     },
//     onFailure: function (err) {
//       return res.status(400).send({
//         errors: [
//           {
//             status: 400,
//             title: err.message,
//           },
//         ],
//       });
//     },
//   });
// };

// const login = async (user) => {
//   if (user.email && user.password) {
//     const payload = {
//       UserPoolId: process.env.COGNITO_POOL_ID,
//       AuthFlow: "ADMIN_NO_SRP_AUTH",
//       ClientId: process.env.COGNITO_CLIENT_ID,
//       AuthParameters: {
//         USERNAME: user.email,
//         PASSWORD: user.password,
//       },
//     };
//     cognitoIdentityServiceProvider.adminInitiateAuth(
//       payload,
//       async (err, data) => {
//         if (err) {
//           res.status(400).send({
//             errors: [
//               {
//                 status: 400,
//                 title: err.message,
//               },
//             ],
//           });
//         } else {
//           var userObject = await modelObj.models.User.findOne({
//             email: user.email,
//           });
//           //Include the user's permissions in the login response
//           if (userObject.role.length) {
//             var role = await modelObj.models.role.findOne({
//               _id: userObject.role[0],
//             });
//             var permissions = await modelObj.models.rolepermission.find({
//               _id: { $in: role.rolePermissions },
//             });
//             var permissionsList = permissions.map((x) => x.name);
//           } else {
//             var permissionsList = [];
//           }

//           res.status(200).send({
//             status: 200,
//             title: "Login successful",
//             email: user.email,
//             userId: userObject._id,
//             username: userObject.userName,
//             scoreboardRolePermissions: permissionsList,
//             ...data,
//           });
//         }
//       }
//     );
//   } else {
//     return res.status(400).send({
//       errors: [
//         {
//           status: 400,
//           title: "email and password is required",
//         },
//       ],
//     });
//   }
// };

// const refreshToken = async (user) => {
//   const RefreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({
//     RefreshToken: user.refreshToken,
//   });
//   const userData = {
//     Username: user.email,
//     Pool: userPool,
//   };

//   const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
//   console.log("COGNITO USER: ", cognitoUser);

//   cognitoUser.refreshSession(RefreshToken, (err, session) => {
//     if (err) {
//       console.log("REFRESH ERR: ", err);
//       return res.status(400).send({
//         errors: [
//           {
//             status: 400,
//             title: err.message,
//           },
//         ],
//       });
//     } else {
//       let retObj = {
//         access_token: session.accessToken.jwtToken,
//         id_token: session.idToken.jwtToken,
//         refresh_token: session.refreshToken.token,
//       };
//       console.log("Good refresh");
//       return res.json(retObj);
//     }
//   });
// };

// const logout = async (accesstoken) => {
//   const params = {
//     AccessToken: accesstoken,
//   };
//   cognitoIdentityServiceProvider.globalSignOut(params, (err, data) => {
//     if (err) {
//       return res.status(400).send({
//         errors: [
//           {
//             status: 400,
//             title: err.message,
//           },
//         ],
//       });
//     } else {
//       return res.status(200).send({
//         status: 200,
//         title: "Sign out successful",
//       });
//     }
//   });
// };

// const confirm = async (user) => {
//   if (user.email && user.otp) {
//     const userData = {
//       Username: user.email,
//       Pool: userPool,
//     };

//     let cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
//     cognitoUser.confirmRegistration(user.otp, true, (err, result) => {
//       if (err) {
//         return res.status(400).send({
//           errors: [
//             {
//               status: 400,
//               title: err.message,
//             },
//           ],
//         });
//       } else {
//         return res.status(200).send({
//           status: 200,
//           title: "User confirmed.",
//         });
//       }
//     });
//   } else {
//     return res.status(400).send({
//       errors: [
//         {
//           status: 400,
//           title: "email and otp is required",
//         },
//       ],
//     });
//   }
// };

// const resendcode = async (user) => {
//   if (user.email) {
//     const params = {
//       Username: user.email,
//       ClientId: process.env.COGNITO_CLIENT_ID,
//     };
//     cognitoIdentityServiceProvider.resendConfirmationCode(
//       params,
//       (err, result) => {
//         if (err) {
//           console.log(err);
//         } else {
//           console.log(result);
//           return res.status(200).send({
//             status: 200,
//             title: "Confirmation code re-sent.",
//           });
//         }
//       }
//     );
//   } else {
//     return res.status(400).send({
//       errors: [
//         {
//           status: 400,
//           title: "email is required",
//         },
//       ],
//     });
//   }
// };

// const verifyPhone = async (user) => {};

// const confirmPhoneCode = async () => {};
