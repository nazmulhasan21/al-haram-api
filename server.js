const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config({
  path: './config.env',
});

const app = require('./app');

// -> Connect the database
const database = 'mongodb://0.0.0.0:27017/al-haram-app';

mongoose.connect(database).then((con) => {
  console.log('DB connection Successfully!');
});

// -> Start the server

app.listen(process.env.PORT || 5000, () => {
  console.log(`Application is running on port ${process.env.PORT || 5000}  `);
});
