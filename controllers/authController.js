const { promisify } = require('util');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('../utils/appError');

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
    const token = createToken(user.id);
    // Remove the password from the output
    user.password = undefined;
    res.status(200).json({
      status: 'success',
      message: 'Login successfully',
      token,
    });
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
    });
  } catch (err) {
    err.statusCode = err.statusCode || 400;
    next(err);
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
