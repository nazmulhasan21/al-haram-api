const express = require('express');
const router = express.Router();

const { signupValidate } = require('../middleware/inputValidation');
const authController = require('../controllers/authController');

router.post('/signup', signupValidate, authController.signup);

router.post('/login', authController.login);
module.exports = router;
