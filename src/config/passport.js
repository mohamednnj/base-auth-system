// src/config/passport.js
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import bcrypt from 'bcrypt';
import User from '../models/User.js';

dotenv.config();

const {
    JWT_SECRET,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CALLBACK_URL,
} = process.env;

export default function initPassport() {
    // Local
    passport.use('local', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        session: false,
    }, async (email, password, done) => {
        try {
            const user = await User.findOne({ email: email.toLowerCase() });
            if (!user || !user.passwordHash) return done(null, false, { message: 'Invalid credentials' });
            const ok = await bcrypt.compare(password, user.passwordHash);
            if (!ok) return done(null, false, { message: 'Invalid credentials' });
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }));

    // Google
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails && profile.emails[0] && profile.emails[0].value;
            let user = await User.findOne({ $or: [{ googleId: profile.id }, { email }] });
            if (user) {
                if (!user.googleId) {
                    user.googleId = profile.id;
                    await user.save();
                }
                return done(null, user);
            }
            user = new User({
                name: profile.displayName,
                email,
                googleId: profile.id,
                isEmailVerified: false,
            });
            await user.save();
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }));

    // JWT
    const opts = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: JWT_SECRET,
    };
    passport.use(new JwtStrategy(opts, async (payload, done) => {
        try {
            const user = await User.findById(payload.sub);
            if (!user) return done(null, false);
            return done(null, user);
        } catch (err) {
            return done(err, false);
        }
    }));
}
