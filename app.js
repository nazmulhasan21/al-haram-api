const express = require('express');
const bodyParser = require('body-parser');

// const helmet = require('helmet');

// Destructuring environment variables

const api = require('./routes/routes');
const globalErrHandler = require('./controllers/errorController');
const AppError = require('./utils/appError');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'OPTIONS, GET, POST, PUT, PATCH, DELETE'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// // -> Allow Cross-Origin requests
// app.use(cors());

// -> Set security HTTP headers
// app.use(helmet());

// -> Body parser, reading data from body into req.body
app.use(
  express.json({
    limit: '16kb',
  })
);

// Use Routes

app.use('/api/v1', api);

// handle undefined Routes
app.use('*', (req, res, next) => {
  const err = new AppError(404, 'fail', 'undefined route');
  next(err, req, res, next);
});

app.use(globalErrHandler);
module.exports = app;
