const nodemailer = require('nodemailer');

module.exports = async (email, subject, html) => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'andriodnazmul@gmail.com',
        pass: 'na168168',
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
    await transporter.sendMail({
      from: '"Verify your email" <andriodnazmul@gmail.com>',
      to: email,
      subject: subject,
      html: html,
    });
    console.log('Email sent Successfully');
    return true;
  } catch (err) {
    // console.log(err);
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    return err;
  }
};
