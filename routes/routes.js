const api = require('express').Router();

const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');

api.use('/user-auth', authRoutes);
api.use('/user', userRoutes);

module.exports = api;
