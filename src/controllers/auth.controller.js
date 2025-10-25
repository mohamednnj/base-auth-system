// src/controllers/auth.controller.js
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import crypto from 'crypto';
import User from '../models/User.js';
import generateOTP from '../utils/generateOTP.js';
import {sendMail} from '../utils/mailer.js';

const {
    JWT_SECRET,
    JWT_EXPIRES_IN = '7d',
    APP_URL = 'http://localhost:3000',
} = process.env;

function signToken(user) {
    return jwt.sign({
        sub: user._id.toString(),
        iat: Math.floor(Date.now() / 1000),
    }, JWT_SECRET, {expiresIn: JWT_EXPIRES_IN});
}

const authController = {
    googleAuth: (req, res, next) => {
        passport.authenticate('google', {scope: ['profile', 'email']})(req, res, next);
    },

    googleCallback: (req, res, next) => {
        passport.authenticate('google', async (err, user, info) => {
            if (err) return next(err);
            if (!user) return res.status(401).json({message: 'Google auth failed'});

            if (!user.isEmailVerified) {
                const otp = generateOTP(6);
                user.otp = otp;
                user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
                await user.save();

                try {
                    await sendMail({
                        to: user.email,
                        subject: 'Email verification - OTP',
                        html: `<p>Your verification OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`
                    });
                } catch (mailErr) {
                    console.error('Failed to send OTP email', mailErr);
                }
            }

            const token = signToken(user);

            return res.json({
                token,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    isEmailVerified: user.isEmailVerified,
                }
            });
        })(req, res, next);
    },

    signup: async (req, res) => {
        try {
            const {name, email, password} = req.body;
            if (!email || !password) return res.status(400).json({message: 'Email and password required'});

            let existing = await User.findOne({email: email.toLowerCase()});
            if (existing) return res.status(409).json({message: 'Email already registered'});

            const salt = await bcrypt.genSalt(10);
            const passwordHash = await bcrypt.hash(password, salt);

            const otp = generateOTP(6);
            const user = new User({
                name,
                email: email.toLowerCase(),
                passwordHash,
                isEmailVerified: false,
                otp,
                otpExpires: new Date(Date.now() + 10 * 60 * 1000),
            });
            await user.save();

            try {
                await sendMail({
                    to: user.email,
                    subject: 'Email verification - OTP',
                    html: `<p>Your verification OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`
                });

            } catch (err) {
                console.error('send mail error', err);
            }

            return res.status(201).json({message: 'User created. OTP sent to email.'});
        } catch (err) {
            console.error(err);
            return res.status(500).json({message: 'Server error'});
        }
    },

    signin: (req, res, next) => {
        passport.authenticate('local', {session: false}, (err, user, info) => {
            if (err) return next(err);
            if (!user) return res.status(401).json({message: info && info.message ? info.message : 'Login failed'});

            const token = signToken(user);
            return res.json({
                token,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    isEmailVerified: user.isEmailVerified,
                }
            });
        })(req, res, next);
    },

    verifyEmail: async (req, res) => {
        try {
            const {email, otp} = req.body;
            if (!email || !otp) return res.status(400).json({message: 'Email and OTP required'});

            const user = await User.findOne({email: email.toLowerCase()});
            if (!user) return res.status(404).json({message: 'User not found'});
            if (user.isEmailVerified) return res.json({message: 'Email already verified'});

            if (!user.otp || !user.otpExpires) return res.status(400).json({message: 'No OTP found. Request a new one.'});
            if (new Date() > user.otpExpires) return res.status(400).json({message: 'OTP expired'});
            if (user.otp !== otp) return res.status(400).json({message: 'Invalid OTP'});

            user.isEmailVerified = true;
            user.otp = undefined;
            user.otpExpires = undefined;
            await user.save();

            return res.json({message: 'Email verified'});
        } catch (err) {
            console.error(err);
            return res.status(500).json({message: 'Server error'});
        }
    },

    resendOtp: async (req, res) => {
        try {
            const {email} = req.body;
            if (!email) return res.status(400).json({message: 'Email required'});

            const user = await User.findOne({email: email.toLowerCase()});
            if (!user) return res.status(404).json({message: 'User not found'});
            if (user.isEmailVerified) return res.status(400).json({message: 'Email already verified'});

            const otp = generateOTP(6);
            user.otp = otp;
            user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
            await user.save();

            try {
                await sendMail({
                    to: user.email,
                    subject: 'Resend OTP - Email verification',
                    html: `<p>Your verification OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`
                });
            } catch (mailErr) {
                console.error('Failed to send OTP email', mailErr);
            }

            return res.json({message: 'OTP resent to email'});
        } catch (err) {
            console.error(err);
            return res.status(500).json({message: 'Server error'});
        }
    },

    forgetPassword: async (req, res) => {
        try {
            const {email} = req.body;
            if (!email) return res.status(400).json({message: 'Email required'});

            const user = await User.findOne({email: email.toLowerCase()});
            if (!user) return res.status(404).json({message: 'User not found'});

            const resetToken = crypto.randomBytes(32).toString('hex');
            const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

            user.resetPasswordToken = hashedToken;
            user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000);
            await user.save();

            const resetLink = `${APP_URL}/reset-password?token=${resetToken}&email=${encodeURIComponent(user.email)}`;

            try {
                await sendMail({
                    to: user.email,
                    subject: 'Password reset',
                    html: `<p>Click the link to reset your password (valid 1 hour): <a href="${resetLink}">${resetLink}</a></p>`
                });
            } catch (mailErr) {
                console.error('Failed to send reset email', mailErr);
            }

            return res.json({message: 'Reset email sent if account exists'});
        } catch (err) {
            console.error(err);
            return res.status(500).json({message: 'Server error'});
        }
    },

    requestPasswordReset : async (req, res) => {
        try {
            const { email } = req.body;
            if (!email) return res.status(400).json({ message: "Email is required" });

            const user = await User.findOne({ email });
            if (!user) return res.status(404).json({ message: "User not found" });

            // Generate random reset token
            const resetToken = crypto.randomBytes(32).toString("hex");
            const resetTokenExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

            // Save token & expiry in DB
            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = resetTokenExpires;
            await user.save();

            // Create reset link (frontend or API endpoint)
            const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

            // Send email
            await sendMail({
                to: email,
                subject: "Reset Your Password",
                html: `
        <h2>Reset Your Password</h2>
        <p>We received a request to reset your password.</p>
        <p>Click the link below to set a new password (valid for 15 minutes):</p>
        <a href="${resetLink}" 
           style="background:#007bff;color:white;padding:10px 20px;border-radius:5px;text-decoration:none">
           Reset Password
        </a>
      `,
            });

            res.status(200).json({ message: "Password reset link sent to your email" });
        } catch (err) {
            console.error("❌ Error in requestPasswordReset:", err);
            res.status(500).json({ message: "Server error" });
        }
    },

    me: async (req, res) => {
        try {
            const user = req.user;

            try {
                await sendMail({
                    to: user.email,
                    subject: 'Your profile',
                    html: `<h3>Your profile</h3>
                 <p>Name: ${user.name || ''}</p>
                 <p>Email: ${user.email}</p>
                 <p>Verified: ${user.isEmailVerified}</p>`
                });
            } catch (mailErr) {
                console.error('Failed to send profile email', mailErr);
            }

            return res.json({
                id: user._id,
                name: user.name,
                email: user.email,
                isEmailVerified: user.isEmailVerified,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
            });
        } catch (err) {
            console.error(err);
            return res.status(500).json({message: 'Server error'});
        }
    },

    // 🟢 Reset Password (validate token + change password)
    resetPasswordHandel : async (req, res) => {
        try {
            const { token } = req.params;
            const { newPassword } = req.body;
            console.log("params ",token);
            if (!token || !newPassword)
                return res.status(400).json({ message: "Missing data" });

            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: {$gt: Date.now()}, // still valid
            });

            if (!user) return res.status(400).json({ message: "Invalid or expired token" });

            // Hash new password
            user.password = newPassword; // ⚠️ hash with bcrypt before saving
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            res.status(200).json({ message: "Password reset successful" });
        } catch (err) {
            console.error("❌ Error in resetPassword:", err);
            res.status(500).json({ message: "Server error" });
        }
    }
};

export default authController;
