const userModel = require("../model/user");
const userLogsModel = require("../model/user_logs");
const apiResponse = require("../helper/apiResponse");
const apiRequest = require("../helper/apiRequest");
const { hashString, infoLog, errorLog, isEmailFormat, normalizeMobileNumber } = require("../helper/common");
const moment = require('moment');

exports.getUser = async (req, res) => {
  try {
    const userList = await userModel.getUser();
    if (!userList) { return apiResponse.notFoundResponse(res, "User not found"); }
    return apiResponse.successResponseWithData(res, "Success", userList);
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

exports.getDelayUser = async (req, res) => {
  try {
    const userList = await userModel.getUser();
    if (!userList) { return apiResponse.notFoundResponse(res, "User not found"); }
    setTimeout(() => { return apiResponse.successResponseWithData(res, "Success", userList); }, 30000);
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok /////////////
exports.userLogin = async (req, res) => {
  try {
    const { user_id, password } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'password', message: 'Password is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        infoLog(message);
        return apiResponse.badRequestResponse(res, message);
      }
    }
    console.log('Normalize' , (isEmailFormat(user_id) ? user_id : normalizeMobileNumber(user_id)))
    const data = { user_id: user_id, password: password };
    const result = await userModel.userLogin(data);
    if (!result) { return apiResponse.badRequestResponse(res, "Invalid User ID and Password"); }
    const { user_name, user_level, user_token, refresh_token } = result;
    infoLog(`User Login Success - User ID: ${user_id}`);
    apiResponse.successResponseWithData(res, "Success", { user_name, user_level, user_token, refresh_token });
  } catch (error) {
    errorLog("Error fetching user: " + error.message);
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok /////////////
exports.createUser = async (req, res) => {
  try {
    const { user_id, user_name, password, user_level } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'user_name', message: 'Username is required' },
      { field: 'password', message: 'Password is required' },
      { field: 'user_level', message: 'User Level is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    const existingUser = await userModel.getUserById(user_id);
    if (existingUser) {
      return apiResponse.conflictResponse(res, "User ID already exists");
    }
    const data = { user_id: user_id, user_name: user_name, password: password, role_code: user_level };
    const result = await userModel.createUser(data);
    return apiResponse.successResponseWithData(res, "User created successfully", result);
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error"
    );
  }
};

////////// it is ok /////////////
exports.userSignUp = async (req, res) => {
  try {
    const { user_id, secret_key } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'secret_key', message: 'Secret key is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    const key = process.env.SECRET_KEY;
    const secretHash = hashString(key);
    console.log(secretHash);
    
    if (secret_key !== secretHash) {
      return apiResponse.conflictResponse(res, "Invalid Secret Key");
    }
    const now = moment();
    const data = { user_id: user_id, created_date: now.format('YYYY-MM-DD') };
    const count = await userLogsModel.checkUserLogs(data);
    if (count < process.env.OTP_MAX_LIMIT) {
      const isEmail = isEmailFormat(user_id)
      const params = isEmail ? { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, toemail: user_id, body_template: 'Dear User, your verification code is {otp}', subject: 'Email Verification', sender_info: 'Mock API', timeout_limit: 3 } :
        { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, phoneno: user_id, msg_template: 'Dear User, your verification code is {otp}', sender_info: 'ConnectMM', timeout_limit: 3 };
      const response = await apiRequest.post(process.env.GATEWAY_HOST + (isEmail ? 'email/sendotp' : 'sms/sendotp'), params);
      if (response.data && response.data.returncode === '300') {
        console.log('Response data:', response.data);
        const result = { user_id: user_id, session: response.data.otpsession }
        userLogsModel.createUserLogs(data)
        return apiResponse.successResponseWithData(res, "Success", result);
      }
      return apiResponse.conflictResponse(res, "Something is wrong");
    } else {
      return apiResponse.badRequestResponse(res, 'OTP limit has reached to maximum request. Please try again later');
    }
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok /////////////
exports.verifyUser = async (req, res) => {
  try {
    const { user_id, session, otp } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'session', message: 'Session is required' },
      { field: 'otp', message: 'OTP is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    const isEmail = isEmailFormat(user_id)
    const params = isEmail ? { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, toemail: user_id, otp: otp, otpsession: session } :
      { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, phoneno: user_id, otp: otp, otpsession: session };
    const response = await apiRequest.post(process.env.GATEWAY_HOST + (isEmail ? 'email/checkotp' : 'sms/checkotp'), params);
    if (response.data) {
      if (response.data.returncode === '300') {
        const result = await userModel.signupUser({ user_id: user_id });
        return apiResponse.successResponseWithData(res, "User account has been created successfully", result);
      } else {
        return apiResponse.conflictResponse(res, response.data.message);
      }
    }
    return apiResponse.conflictResponse(res, "Something is wrong");
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok ///////////// 
exports.resetPassword = async (req, res) => {
  try {
    const { user_id, secret_key } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'secret_key', message: 'Secret key is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    const key = process.env.SECRET_KEY;
    const secretHash = hashString(key);
    if (secret_key !== key) {
      return apiResponse.conflictResponse(res, "Invalid Secret Key");
    }
    const existingUser = await userModel.getUserById(user_id);
    if (existingUser) {
      const now = moment();
      const data = { user_id: user_id, created_date: now.format('YYYY-MM-DD') };
      const count = await userLogsModel.checkUserLogs(data);
      if (count < process.env.OTP_MAX_LIMIT) {
        const isEmail = isEmailFormat(user_id)
        const params = isEmail ? { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, toemail: user_id, body_template: 'Dear User, your verification code is {otp}', subject: 'Email Verification', sender_info: 'Mock API', timeout_limit: 3 } :
          { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, phoneno: user_id, msg_template: 'Dear User, your verification code is {otp}', sender_info: 'ConnectMM', timeout_limit: 3 };
        const response = await apiRequest.post(process.env.GATEWAY_HOST + (isEmail ? 'email/sendotp' : 'sms/sendotp'), params);
        if (response.data && response.data.returncode === '300') {
          const result = { user_id: user_id, session: response.data.otpsession }
          userLogsModel.createUserLogs(data)
          return apiResponse.successResponseWithData(res, "Success", result);
        }
        return apiResponse.conflictResponse(res, "Something is wrong");
      } else {
        return apiResponse.badRequestResponse(res, 'OTP limit has reached to maximum request. Please try again later');
      }
    }
    return apiResponse.conflictResponse(res, "User doesn't exist");
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok /////////////
exports.verifyOTP = async (req, res) => {
  try {
    const { user_id, session, otp } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'session', message: 'Session is required' },
      { field: 'otp', message: 'OTP is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    const isEmail = isEmailFormat(user_id)
    const params = isEmail ? { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, toemail: user_id, otp: otp, otpsession: session } :
      { appid: process.env.APP_ID, accesskey: process.env.ACCESS_KEY, phoneno: user_id, otp: otp, otpsession: session };
    const response = await apiRequest.post(process.env.GATEWAY_HOST + (isEmail ? 'email/checkotp' : 'sms/checkotp'), params);
    if (response.data) {
      if (response.data.returncode === '300') {
        const result = await userModel.resetPasswordKey({ user_id: user_id });
        return apiResponse.successResponseWithData(res, "OTP has been verified successfully", result);
      } else {
        return apiResponse.conflictResponse(res, response.data.message);
      }
    }
    return apiResponse.conflictResponse(res, "Something is wrong");
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};

////////// it is ok /////////////
exports.changePassword = async (req, res) => {
  try {
    const { user_id, reset_key, new_password, confirm_password } = req.body;
    const requiredFields = [
      { field: 'user_id', message: 'User ID is required' },
      { field: 'reset_key', message: 'Reset Key is required' },
      { field: 'new_password', message: 'New Password is required' },
      { field: 'confirm_password', message: 'Confirmed Password is required' }
    ];
    for (let i = 0; i < requiredFields.length; i++) {
      const { field, message } = requiredFields[i];
      if (!req.body[field]) {
        return apiResponse.badRequestResponse(res, message);
      }
    }
    if (new_password !== confirm_password) {
      return apiResponse.badRequestResponse(res, "New password and confirmed password doesn't match");
    }
    const existingUser = await userModel.getUserById(user_id);
    if (existingUser) {
      const result = await userModel.changePassword({ user_id: user_id, reset_key: reset_key, new_password: new_password });
      return apiResponse.successResponseWithData(res, "Your password has been changed successfully", result);
    }
    return apiResponse.conflictResponse(res, "User doesn't exist");
  } catch (error) {
    return apiResponse.ServerErrorResponse(res, error.message || "Internal Server Error");
  }
};
