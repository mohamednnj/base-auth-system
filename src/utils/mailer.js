// src/utils/mailer.js
import {google} from "googleapis";
import dotenv from 'dotenv';

dotenv.config();
const {
    GMAIL_CLIENT_ID,
    GMAIL_CLIENT_SECRET,
    GMAIL_REDIRECT_URI = "https://developers.google.com/oauthplayground",
    GMAIL_REFRESH_TOKEN,
    APP_EMAIL_FROM,
} = process.env;

const oauth2Client = new google.auth.OAuth2(
    GMAIL_CLIENT_ID,
    GMAIL_CLIENT_SECRET,
    GMAIL_REDIRECT_URI
);

oauth2Client.setCredentials({refresh_token: GMAIL_REFRESH_TOKEN});

const gmail = google.gmail({version: "v1", auth: oauth2Client});

function makeBody(to, subject, html) {
    const str = [
        `From: ${APP_EMAIL_FROM}`,
        `To: ${to}`,
        `Subject: ${subject}`,
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=UTF-8",
        "",
        html,
    ].join("\n");

    return Buffer.from(str)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

export async function sendMail({to, subject = "Your OTP Code", html}) {
    if (!to) {
        console.error("❌ No recipient email provided!");
        return;
    }

    try {
        const raw = makeBody(to, subject, html);

        const res = await gmail.users.messages.send({
            userId: "me",
            requestBody: {raw},
        });

        console.log("✅ Email sent successfully");
        return res.data;
    } catch (err) {
        console.error("❌ Mail send error", err);
        throw err;
    }
}
