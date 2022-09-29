const express = require('express');
const router = express.Router();

const { signupValidate } = require('../middleware/inputValidation');
const authController = require('../controllers/authController');
const {
  generate2FACode,
  verify2FACode,
  enabled2FACode,
} = require('../controllers/2FACode');

router.post('/signup', signupValidate, authController.signup);

router.post('/login', authController.login);
router.post('/2fa/generate', generate2FACode);

router.post('/2fa/enabled', enabled2FACode);
router.post('/2fa/verify', verify2FACode);

router.post(
  '/send-forget-password-verification-link',

  authController.sendForgetPasswordVerificationLink
);
router.patch('/:token/reset-password', authController.resatPassword);

module.exports = router;
