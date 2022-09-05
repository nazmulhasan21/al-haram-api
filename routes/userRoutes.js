const express = require('express');
const router = express.Router();

const { updateMeValidate } = require('../middleware/inputValidation');
const userController = require('../controllers/userController');
const { protect } = require('../controllers/authController');

// Protect all routes after this middleware
router.use(protect);

router
  .route('/me')
  .get(userController.me)
  .patch(updateMeValidate, userController.updateMe);

router.delete('/me/delete', userController.deleteMe);
// Only admin have permission to access for the below APIs

module.exports = router;
