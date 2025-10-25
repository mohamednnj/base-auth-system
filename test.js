import { sendMail } from "./src/utils/mailer.js";


const otp = "123456";

await sendMail({
    to: "mohamedelsary960@gmail.com",
    subject: "Your OTP Code",
    html: `<p>Your verification code is <b>${otp}</b></p>`,
});
