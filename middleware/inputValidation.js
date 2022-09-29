const { body } = require('express-validator');
const User = require('../models/userModel');

exports.signupValidate = [
  body('email')
    .trim()
    .isEmail()
    .withMessage((value) => {
      return `'${value}' not a valid email.`;
    })
    .notEmpty()
    .withMessage('Please enter any valid email.')
    .custom((value, { req }) => {
      return User.findOne({ email: value }).then((userDoc) => {
        if (userDoc) {
          return Promise.reject('E-Mail address already exists!');
        }
      });
    })
    .normalizeEmail(),

  body('password')
    .trim()
    .isLength({ min: 8 })
    .withMessage('Password  min length 8.'),
  ///.isStrongPassword({ returnScore: false })
  // .withMessage(
  //   'Password must be greater than 8 and contain at least one uppercase letter, one lowercase letter, and one number'
  // ),
  body('name')
    .trim()
    .isLength({ min: 3 })
    .withMessage('Please name min length 3.')
    .matches(/^[a-zA-Z. ]+$/)
    .withMessage('Please enter valid name'),
];

exports.updateMeValidate = [
  body('name')
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Please name min length 3.')
    .matches(/^[a-zA-Z. ]+$/)
    .withMessage('Please enter valid name'),
  body('address')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Type your address properly.'),
  // .matches(/^[a-zA-Z0-9., ]+$/)
  // .withMessage('Please enter valid address'),
  body('institution')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Type institution properly')
    .matches(/^[a-zA-Z0-9., ]+$/)
    .withMessage('Please enter valid institution'),
];

exports.isEmailInput = [
  body('email')
    .trim()
    .isEmail()
    .withMessage((value) => {
      return `'${value}' not a valid email.`;
    })
    .notEmpty()
    .withMessage('Please enter any valid email.')
    .normalizeEmail(),
];
