const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose')

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, minLength: 8 },
    isVerified: { type: Boolean, required: true, default: false },
    passwordResetOtp: { type: String, },
    passwordOtpExpires: { type: Date, },
    otp: { type: String, },
    otpExpires: { type: Date, },
    googleId: { type: String },
    googleToken: { type: String },
    facebookId: { type: String },
    facebookToken: { type: String },
    linkedinId: { type: String },
    linkedinToken: { type: String },
});

userSchema.plugin(passportLocalMongoose)
const User = mongoose.model('User', userSchema);
passport.serializeUser(User.serializeUser())
passport.deserializeUser(User.deserializeUser())

module.exports = User;