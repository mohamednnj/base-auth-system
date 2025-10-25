// src/server.js
import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import passport from 'passport';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import bodyParser from 'body-parser';

import connectDB from './src/config/db.js';
import initPassport from './src/config/passport.js';
import authRoutes from './src/routes/auth.routes.js';

const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/test';

const app = express();

app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// DB

// Passport init
initPassport();
app.use(passport.initialize());

// Routes
app.use('/api/v1/auth', authRoutes);

// health
app.get('/health', (req, res) => res.json({ok: true}));
connectDB(MONGO_URI).then(
    () => {
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
        })
    }
);
