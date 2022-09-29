const { promisify } = require('util');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('../utils/appError');

const sendMail = require('../utils/sendEmail');

// create jwt token
const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    // -> 1 <- check if email and password exist
    if (!email || !password) {
      return next(
        new AppError(400, 'email', 'Please provide email or password', 'fail')
      );
    }

    // -> 2 <- check if user exist and password is correct
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError(401, 'password', 'Email or Password is wrong'));
    }
    // check email verification

    // -> 3 <- All correct , send jwt to client
    if (user.twoFactorAuthEnabled) {
      res.status(200).json({
        status: 'success',
        message: 'Login successfully',
        twoFactorAuthEnabled: true,
        userId: user._id,
      });
    } else {
      const token = createToken(user.id);
      // Remove the password from the output
      user.password = undefined;
      res.status(200).json({
        status: 'success',
        message: 'Login successfully',
        token,
      });
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
    const { name, email, password } = req.body;

    const user = await User.create({
      name,
      email,
      password,
    });
    // -> 3 <- All correct , send jwt to client
    const token = createToken(user.id);
    user.password = undefined;
    res.status(200).json({
      status: 'success',
      message: 'Create account successfully',
      token,
      user,
    });
  } catch (err) {
    err.statusCode = err.statusCode || 400;
    next(err);
  }
};

exports.sendForgetPasswordVerificationLink = async (req, res, next) => {
  try {
    const email = req.body.email.trim();
    // 1. find user this email
    const user = await User.findOne({ email });

    // 2. email doesn't exist
    if (!user)
      return res.status(404).json({
        message: 'User not found  this email',
      });

    // 3. send forget password verification link
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '15m',
    });

    const to = user.email;
    const subject = 'Reset Password Verification Link';
    const html = `<h2> Please click on given link to reset your password</h2>
    <p><a href="http://${req.headers.host}/resetpassword?token=${token}">change password</a></p>`;

    const sent = await sendMail(to, subject, html);
    console.log(sent);

    if (sent == true) {
      res.status(200).json({
        status: 'success',
        message: 'Please check your email and reset your password',
      });
    } else {
      res.status(sent.statusCode).json({
        sent,
      });
    }
  } catch (error) {
    console.log('email', error);
    next(error);
  }
};

// forget password
exports.resatPassword = async (req, res, next) => {
  try {
    const { token } = req.body;
    const password = req.body.password.trim();

    if (token) {
    }

    const user = await User.findOne({ email });
    const otpCode = await OtpCode.findOne({ email, code });
    if (!otpCode || !user) {
      return next(new AppError(401, 'code', `Code is wrong`));
    }

    // expired time
    const expired = otpCode?.expiredAt - new Date().getTime();
    if (expired < 0) {
      const to = { email: email, name: user.name };
      const subject = 'Reset Password Verification Code';
      const templateName = 'sendEmailCode';

      sendVerificationCode(to, subject, templateName);
      return next(
        new AppError(401),
        'code',
        'Code is expired. please check email sending new code'
      );
    }

    user.password = newPassword;
    await user.save();
    await OtpCode.findByIdAndDelete(otpCode?._id);
    res.status(200).json({
      status: 'success',
      message: 'Reset your password successfully',
    });
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
