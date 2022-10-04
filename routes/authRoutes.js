const express = require('express');
const router = express.Router();

const { passwordValidate } = require('../middleware/inputValidation');
const authController = require('../controllers/authController');

router.post('/signup', passwordValidate, authController.signup);
router.post('/google-auth-sign-in', authController.googleAuthSignIn);
router.post('/otp/verify', authController.otpVerify);
router.post('/otp/resent', authController.otpResent);

router.post('/login', authController.login);

router.post(
  '/send-forget-password-verification-otp-code',

  authController.sendForgetPasswordVerificationOtpCode
);
router.patch('/reset-password', passwordValidate, authController.resatPassword);

module.exports = router;
