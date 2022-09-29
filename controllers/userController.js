const { validationResult } = require('express-validator');



const User = require('../models/userModel');
const AppError = require('../utils/appError');

// user/me

// get me
exports.me = async (req, res, next) => {
  try {
    const { user } = req;

    res.status(200).json({
      status: 'success',
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
};

// update  me
exports.updateMe = async (req, res, next) => {
  try {
    const { user } = req;
    const { name, institution, address } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(errors);
    }
    // find user and update me
    const updateMe = await User.findByIdAndUpdate(
      user._id,
      {
        $set: { name, institution, address },
      },
      { new: true, runValidators: true }
    );

    // send res
    res.status(200).json({
      status: 'success',
      message: 'Your Profile update successfully',
      user: updateMe,
    });
  } catch (error) {
    next(error);
  }
};

// delete me
exports.deleteMe = async (req, res, next) => {
  try {
    const { user } = req;

    const delUser = await User.findByIdAndDelete(user._id);
    if (!delUser) {
      return next(new AppError(402, 'fail', 'Something wrong, Try again'));
    }
    res.status(204).json({
      status: 'success',
      message: 'Your account delete successfully',
      data: null,
    });
  } catch (error) {
    next(error);
  }
};
