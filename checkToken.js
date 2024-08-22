const jwt = require("jsonwebtoken");
const apiResponse = require("../helper/apiResponse");
require("dotenv").config();
const moment = require("moment");
const sql = require("../helper/database");
const { infoLog, errorLog } = require("../helper/common");

const verifyToken = (token, secret) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secret, (err, decoded) => {
      console.log(decoded, "Decoded");
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};

const getUserOrGuestDetails = async (decoded, access_id, table, idField) => {
  const query = `SELECT * FROM ${table} WHERE ${idField} = $1`;
  const result = await sql.query(query, [access_id]);
  return result.rowCount === 1 ? result.rows[0] : null;
};

const sendUnauthorizedResponse = (res, message) => {
  infoLog(`Unauthorized: ${message}`);
  return apiResponse.unauthorizedResponse(res, message);
};

const checkToken = async (req, res) => {
  try {
    const access_id = req.headers["access_id"];
    const token = req.headers["access_token"];
    if (!access_id && !token) {
      return sendUnauthorizedResponse(res, "Access ID and token are missing");
    }
    if (!access_id) {
      return sendUnauthorizedResponse(res, "Access ID is missing");
    }
    if (!token) {
      return sendUnauthorizedResponse(res, "Token is missing");
    }
    try {
      const userDecoded = await verifyToken(token, process.env.USER_SECRET_KEY);
      if (userDecoded && userDecoded.userId === access_id) {
        const user = await getUserOrGuestDetails(userDecoded, access_id, "tbl_user", "user_id");
        if (user) {
          const issueAt = moment.unix(userDecoded.iat).format('YYYY-MM-DD HH:mm:ss');
          const expiresAt = moment.unix(userDecoded.exp).format('YYYY-MM-DD HH:mm:ss');
          const userId = userDecoded.userId;
          infoLog(`User ID: ${access_id}, User Token: ${token}`);
          return apiResponse.successResponseWithData(res, "User token is valid", { userId: userId, issuedAt: issueAt, expiresAt: expiresAt });
        }
      }
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return sendUnauthorizedResponse(res, "Expired");
      }
    }

    try {
      const guestDecoded = await verifyToken(token, process.env.GUEST_SECRET_KEY);
      if (guestDecoded && guestDecoded.guestId === access_id) {
        const guest = await getUserOrGuestDetails(guestDecoded, access_id, "tbl_guest", "client_id");
        if (guest) {
          const issuedAt = moment.unix(guestDecoded.iat).format('YYYY-MM-DD HH:mm:ss');
          const expiresAt = moment.unix(guestDecoded.exp).format('YYYY-MM-DD HH:mm:ss');
          const guestId = guestDecoded.guestId;
          infoLog(`Guest ID: ${access_id}, Guest Token: ${token}`);
          return apiResponse.successResponseWithData(res, "Guest token is valid", {
            guestId: guestId,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
          });
        }
      }
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return sendUnauthorizedResponse(res, "Expired");
      }
    }
    return sendUnauthorizedResponse(res, "Unauthorized");
  } catch (error) {
    errorLog("Error Checking Token: " + error.message);
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

module.exports = { checkToken };
