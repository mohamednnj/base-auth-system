// src/models/User.js
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    name: {type: String},
    email: {type: String, required: true, unique: true, lowercase: true, trim: true},
    passwordHash: {type: String},
    googleId: {type: String, index: true, sparse: true},
    isEmailVerified: {type: Boolean, default: false},
    otp: {type: String},
    otpExpires: {type: Date},
    resetPasswordToken: {type: String},
    resetPasswordExpires: {type: Date},
}, {timestamps: true});

UserSchema.pre('save', async function (next) {
    if (this.isModified('googleId')) this.set('isEmailVerified', true)
    next();
})
export default mongoose.model('User', UserSchema);
