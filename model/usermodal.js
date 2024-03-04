// models/user.js

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profileImage: { type: String, required: true },
  socketId: String,
  token: String,
  verified: { type: Boolean, default: false },
});


const User = mongoose.model('User', userSchema);

module.exports = User;
