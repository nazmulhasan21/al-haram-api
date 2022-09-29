const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');

const generateSpeakeasySecretCode = () => {
  const secretCode = speakeasy.generateSecret({
    name: 'app_name',
  });
  return {
    otpauthUrl: secretCode.otpauth_url,
    base32: secretCode.base32,
  };
};

// const returnQRCode = (data, res) => {
//   QRCode.toFileStream(res, data);
// };

exports.generate2FACode = async (req, res, next) => {
  try {
    const token = req.body.token;
    const decode = jwt.verify(token, process.env.JWT_SECRET);
    const { otpauthUrl, base32 } = generateSpeakeasySecretCode();

    await User.findOneAndUpdate(decode.id, {
      twoFactorTempSecret: base32,
    });
    //   returnQRCode(otpauthUrl, res);
    QRCode.toDataURL(otpauthUrl, (err, data_url) => {
      if (!err) {
        res.status(200).json({
          status: 'pending',
          userId: decode.id,
          data_url,
          base32,
        });
      } else {
        return next(err);
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.enabled2FACode = async (req, res, next) => {
  try {
    const { userId, code } = req.body;

    const user = await User.findById(userId);

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorTempSecret,
      encoding: 'base32',
      token: code,
    });
    if (verified) {
      (user.secret = user.twoFactorTempSecret),
        (user.twoFactorAuthEnabled = true);
      user.twoFactorTempSecret = undefined;
      await user.save();
      // create token
      id = user._id;
      const token = jwt.sign({ id }, process.env.JWT_SECRET);

      res.status(200).json({
        status: 'success',
        verified: true,
        token,
      });
    } else {
      res.status(403).json({
        status: 'fail',
        verified: false,
      });
    }
  } catch (error) {
    next(error);
  }
};

// login with 2fa code verify
exports.verify2FACode = async (req, res, next) => {
  try {
    const { userId, code } = req.body;

    const user = await User.findById(userId);

    const verified = speakeasy.totp.verify({
      secret: user.secret,
      encoding: 'base32',
      token: code,
    });
    if (verified) {
      // create token
      id = user._id;
      const token = jwt.sign({ id }, process.env.JWT_SECRET);

      res.status(200).json({
        status: 'success',
        verified: true,
        token,
      });
    } else {
      res.status(403).json({
        status: 'fail',
        verified: false,
      });
    }
  } catch (error) {
    next(error);
  }
};
