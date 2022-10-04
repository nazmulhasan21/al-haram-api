const { promisify } = require('util');
const { validationResult } = require('express-validator');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('../utils/appError');

const sendMail = require('../utils/sendEmail');
const { sendOtpVia, verifyOtp, phonNumberValidation } = require('../utils/fun');

// create jwt token
const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};

exports.login = async (req, res, next) => {
  try {
    let { phone, countryCode, password } = req.body;
    phone = await phonNumberValidation(countryCode, phone, res, next);
    const error = {};
    if (phone) {
      const user = await User.findOne({
        phone,
      }).select('+password');

      if (!user || !(await user.correctPassword(password, user.password))) {
        return next(
          new AppError(400, 'phone', 'Phone number or password is wrong')
        );
      }
      // all okay then save user info in db

      if (user && !user.phoneVerified) {
        // send otp via sms
        const sendOtp = await sendOtpVia('sms', user.phone, next);
        // if send otp code
        if (sendOtp) {
          return res.status(200).json({
            status: 'success',
            message: 'Send otp code successfully',
            phoneVerified: false,
          });
        } else {
          error.message = 'Create account and Code send fail';
          return res.status(400).json({ error });
        }
      } else if (user && user.phoneVerified) {
        // -> 3 <- All correct , send jwt to client
        // create token and send user
        const token = createToken(user._id);
        // Remove the password from the output
        user.password = undefined;
        return res.json({
          status: 'success',
          message: 'Login successfully',
          phoneVerified: true,
          token,
          user,
        });
      }
    }
  } catch (err) {
    next(err);
  }
};

exports.signup = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(errors);
    }
    let { phone, countryCode, password } = req.body;
    phone = await phonNumberValidation(countryCode, phone, res, next);
    const error = {};
    if (phone) {
      const phoneExist = await User.findOne({
        phone,
      });
      const userExist = phoneExist;
      if (userExist) {
        return next(new AppError(400, 'phone', 'Phone number already exist'));
      }
      // all okay then save user info in db

      // send otp in user phone vai sms
      const sendOtp = await sendOtpVia('sms', phone, next);
      if (sendOtp) {
        await User.create({
          phone,
          password,
        });
        return res.status(200).json({
          status: 'success',
          message: 'Create account successfully',
          phoneVerified: false,
        });
      } else {
        error.message = 'Create account and Code send fail';
        return res.status(400).json({ error });
      }
      // -> 3 <- All correct , send jwt to client
    }
    return res.status(400).json({ error });
  } catch (err) {
    err.statusCode = err.statusCode || 400;
    next(err);
  }
};

// google auth verify
async function verify(client, token) {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.CLIENT_ID,
  });
  return ticket.getPayload();
}

exports.googleAuthSignIn = async (req, res, next) => {
  try {
    const { id_token } = req.body;
    // google token verify
    const client = new OAuth2Client(process.env.CLIENT_ID);
    var x = await verify(client, id_token).catch();
    if (x.email_verified) {
      const user = await User.findOne({ email: x.email });
      if (user) {
        // create token;
        const token = createToken(user._id);
        user.password = undefined;
        return res.json({
          status: 'success',
          message: 'Login successfully',
          token,
          user,
        });
      } else if (!user) {
        const user = await User.create({
          name: x.name,
          email: x.email,
          password: x.at_hash,
        });
        // create token
        const token = createToken(user._id);
        user.password = undefined;
        return res.json({
          status: 'success',
          message: 'Login successfully',
          token,
          user,
        });
      }
    } else {
      res.send({
        status: 'fail',
        message: 'User unauthorized',
      });
    }
  } catch (error) {
    next(error);
  }
};

exports.otpVerify = async (req, res, next) => {
  try {
    let { otpCode, phone, countryCode } = req.body;

    phone = await phonNumberValidation(countryCode, phone, res, next);
    const user = await User.findOne({ phone });
    const error = {};
    if (phone && user) {
      const verifySuccess = await verifyOtp(to, otpCode, next);
      if (verifySuccess) {
        await User.updateOne({ phone: to }, { phoneVerified: true });
        return res.json({
          message: 'Verified successfully',
          phoneVerified: true,
        });
      } else {
        error.otpCode = 'Incorrect code. Please try again';
        return res.status(400).json({ error });
      }
    } else if (!user) {
      error.user = 'Not have a account';
      return res.status(400).json({ error });
    }
  } catch (error) {
    next(error);
  }
};

exports.otpResent = async (req, res, next) => {
  try {
    let { phone, countryCode } = req.body;
    phone = await phonNumberValidation(countryCode, phone, res, next);
    const user = await User.findOne({ phone });
    if (phone && user) {
      const sendOtp = await sendOtpVia('sms', phone, next);
      if (sendOtp) {
        return res.status(200).json({
          status: 'success',
          message: 'Resent otp successfully',
          phoneVerified: false,
        });
      }
    }
  } catch (error) {
    next(error);
  }
};

exports.sendForgetPasswordVerificationOtpCode = async (req, res, next) => {
  try {
    let { phone, countryCode } = req.body;
    phone = await phonNumberValidation(countryCode, phone, res, next);
    const user = await User.findOne({ phone });
    const error = {};
    if (phone && user) {
      const sendOtp = await sendOtpVia('sms', phone, next);
      if (sendOtp) {
        return res.status(200).json({
          status: 'success',
          message: 'Resent otp code successfully',
          phoneVerified: false,
        });
      }
    } else if (!user) {
      error.user = 'Not have a account';
      return res.status(400).json({ error });
    }
  } catch (error) {
    next(error);
  }
};
// forget password
exports.resatPassword = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(errors);
    }
    let { otpCode, phone, countryCode } = req.body;
    phone = await phonNumberValidation(countryCode, phone, res, next);
    const user = await User.findOne({ phone });
    const newPassword = req.body.password;
    const error = {};
    if (phone && user) {
      const verifySuccess = await verifyOtp(phone, otpCode, next);
      if (verifySuccess) {
        await User.updateOne({ phone }, { password: newPassword });
        return res.json({
          message: 'Reset your password successfully',
        });
      } else {
        error.otpCode = 'Incorrect code. Please try again';
        return res.status(400).json({ error });
      }
    } else if (!user) {
      error.user = 'Not have a account';
      return res.status(400).json({ error });
    }
  } catch (error) {
    next(error);
  }
};

exports.protect = async (req, res, next) => {
  try {
    // -> 1 <- check if the token is there
    let token;
    if (
      // authHeader
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      // token = authHeader.split(' ')[1];
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) {
      return next(
        new AppError(
          401,
          'token',
          'You are not logged in! Please login in to continue'
        )
      );
    }
    // 2. Verify token
    const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3. check if the user is exist (not deleted)
    const user = await User.findById(decode.id);

    if (!user) {
      return next(new AppError(401, 'user', 'This user is no longer exist'));
    }
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
};
