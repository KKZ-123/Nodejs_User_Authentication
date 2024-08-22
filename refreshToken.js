const jwt = require("jsonwebtoken");
const apiResponse = require("../helper/apiResponse");
require("dotenv").config();
const { infoLog, errorLog, generateToken } = require("../helper/common");

exports.generateRefreshToken = async (req, res) => {
  try {
    const access_token = req.headers["access_id"];
    const refresh_token = req.headers["refresh_token"];
    if (!access_token && !refresh_token) {
      infoLog("Unauthorized: Access ID and refresh token are missing");
      return apiResponse.unauthorizedResponse(
        res,
        "Unauthorized: Access ID and refresh token are missing"
      );
    } else if (!access_token) {
      infoLog("Unauthorized: Access ID is missing");
      return apiResponse.unauthorizedResponse(
        res,
        "Unauthorized: Access ID is missing"
      );
    } else if (!refresh_token) {
      infoLog("Unauthorized: Refresh token is missing");
      return apiResponse.unauthorizedResponse(
        res,
        "Unauthorized: Refresh token is missing"
      );
    } else {
      jwt.verify(
        refresh_token,
        process.env.REFRESH_SECRET_KEY,
        async (err, decoded) => {
          if (err) {
            if (err.name === "TokenExpiredError") {
              infoLog(`Unauthorized: Refresh Token Expired - Refresh Token: ${refresh_token}`);
              return apiResponse.unauthorizedResponse(
                res,
                "Expired"
              );
            } else {
              infoLog(`Unauthorized: Invalid Refresh Token: ${refresh_token}`);
              return apiResponse.unauthorizedResponse(
                res,
                "Unauthorized"
              );
            }
          }
          if (decoded.userId) {
            const userId = access_token;
            if (decoded.userId === userId) {
              let user_token = generateToken({ userId: userId }, process.env.USER_SECRET_KEY, "3m");
              return apiResponse.successResponseWithData(res, "Success", { user_token });
            } else {
              infoLog(`Unauthorized: User Access ID: ${access_token}, Refresh Token: ${refresh_token}`);
              return apiResponse.unauthorizedResponse(
                res,
                "Unauthorized"
              );
            }
          } else if (decoded.guestId) {
            const guestId = access_token;
            if (decoded.guestId === guestId) {
              let guest_token = generateToken({ guestId: guestId }, process.env.GUEST_SECRET_KEY, "3m");
              return apiResponse.successResponseWithData(res, "Success", { guest_token });
            } else {
              infoLog(`Unauthorized: Guest Access ID: ${access_token}, Refresh Token: ${refresh_token}`);
              return apiResponse.unauthorizedResponse(
                res,
                "Unauthorized"
              );
            }
          } else {
            infoLog(`Unauthorized: Invalid Refresh Token: ${refresh_token}`);
            return apiResponse.unauthorizedResponse(
              res,
              "Unauthorized"
            );
          }
        }
      );
    }
  } catch (error) {
    errorLog("Error generating refresh token: " + error.message);
    return apiResponse.ServerErrorResponse(
      res,
      error.message || "Internal Server Error"
    );
  }
};
