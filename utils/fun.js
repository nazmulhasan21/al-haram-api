const { phone: phoneValidator } = require('phone');

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_SERVICE_SID_CODE_4,
  TWILIO_SERVICE_SID_CODE_6,
} = process.env;

const twilio = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

/**
 *send OTP vai email or sms.
 * @param {("email"| "sms")} via - which channel used to send otp
 * @param {string} to If channel is email then its n email address else its its phone number
 * @param {6|4} codeSize You can set code size 4 or 6. default = 6
 * @param {() =>} next express callback
 * @returns {{ accepted: boolean, issue: string }} A object with property 'accepted' and 'issue'. Note: if accepted = true then issue = undefined
 */
module.exports.sendOtpVia = async (via = 'email', to, next, codeSize = 6) => {
  try {
    return true; // remove only this line when re purchased the twilio services
    const otpSend = await twilio.verify
      .services(
        codeSize === 6 ? TWILIO_SERVICE_SID_CODE_6 : TWILIO_SERVICE_SID_CODE_4
      )
      .verifications.create({ to, channel: via });

    if (otpSend.status === 'pending') {
      return true;
    } else {
      return false;
    }
  } catch (error) {
    //  console.log(error);
    next(error);
  }
};

/**
 * Verify OTP
 * @param {!string} to where this code was found?
 * @param {!string} otp what is the code?
 * @param {() =>} next express callback
 * @param {6|4} codeSize You can set code size =6 or 4. default = 6.
 * @returns {boolean} If verify success then true otherwise false.
 */

module.exports.verifyOtp = async (to, otp, next, codeSize = 6) => {
  try {
    return true; // remove only this line when re purchased the twilio services
    const checkedResult = await twilio.verify
      .services(
        codeSize === 6 ? TWILIO_SERVICE_SID_CODE_6 : TWILIO_SERVICE_SID_CODE_4
      )
      .verificationChecks.create({ to, code: otp.toString() });

    if (checkedResult && checkedResult.status === 'approved') {
      return true;
    } else {
      return false;
    }
  } catch (error) {
    next(error);
  }
};

module.exports.phonNumberValidation = async (code, phoneNumber, res, next) => {
  try {
    let phone = phoneNumber;
    let countryCode = code;
    //let { phone, countryCode, password } = req.body;
    phone = !!phone ? String(phone).toLowerCase().trim() : '';
    // phone validation
    let phoneValidation = {},
      phnNmOk,
      isValidCountryCode;
    if (phone && countryCode) {
      const regex = /^[0-9,+]+$/;
      isValidCountryCode = countryCode.match(regex);
      if (isValidCountryCode) {
        phoneValidation = phoneValidator(`${countryCode}${phone}`);
        phnNmOk = phoneValidation.isValid;
      }
    }
    const error = {};
    if (phnNmOk) {
      const phone = phoneValidation.phoneNumber;
      return phone;

      // -> 3 <- All correct , send jwt to client
    } else if (!phnNmOk) {
      if (!countryCode) {
        error.phone = 'Please enter country code!';
      } else if (!isValidCountryCode) {
        error.phone = 'Please enter valid country code!';
      } else if (!phone) {
        error.phone = 'Please enter your phone number!';
      } else if (!phoneValidation.isValid) {
        error.phone = 'Please enter valid phone number';
      }
    }
    return res.status(400).json({ error });
  } catch (err) {
    err.statusCode = err.statusCode || 400;
    next(err);
  }
};
