// src/routes/auth.routes.js
import express from 'express';
import passport from 'passport';
import authCtrl from '../controllers/auth.controller.js';

const router = express.Router();

// Google OAuth
router.get('/google', authCtrl.googleAuth);
router.get('/google/callback', authCtrl.googleCallback);

// Local signup/signin
router.post('/signup', authCtrl.signup);
router.post('/signin', authCtrl.signin);

// verify email via OTP
router.post('/verify-email', authCtrl.verifyEmail);

// resend OTP
router.post('/resend-otp', authCtrl.resendOtp);

// forget password (sends reset link token)
router.post('/forget-password', authCtrl.forgetPassword);

// reset password (use token from email)
router.post('/reset-password', authCtrl.requestPasswordReset);

// generated link to reset password
router.post("/reset-password/:token", authCtrl.resetPasswordHandel);

// Protected route
router.get('/me', passport.authenticate('jwt', { session: false }), authCtrl.me);

export default router;
