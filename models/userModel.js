const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: true,
    },
    twoFactorAuthEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorTempSecret: String,
    secret: String,
  },
  { timestamps: true }
);

// encrypt the password using 'bcryptjs'
// Mongoose -> Document Middleware

userSchema.pre('save', async function (next) {
  // check the password if it is modified
  if (!this.isModified('password')) {
    return next();
  }
  // Hashing the password
  this.password = await bcrypt.hash(this.password, 12);

  next();
});

// This is Instance Method that is gonna be available on all documents in a certain collection
userSchema.methods.correctPassword = async function (
  typedPassword,
  originalPassword
) {
  return await bcrypt.compare(typedPassword, originalPassword);
};
const User = mongoose.model('User', userSchema);
module.exports = User;
