import redis from "../redisClient";
import { Request, Response, NextFunction } from "express";

const loginRateLimiter = async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.headers);
    console.log(req.headers.email);
    const email = req.headers.email;
    console.log(email);

    const max_request = 2;
    const key = `login-credentials ${email}`;
    const max_expire = 60;
    if (!key) {
        return res.status(400).json({ message: "Request email is undefined" });
    }

    try {
        await redis.incr(key);
        const attempts = await redis.get(key);
        console.log(attempts, "count");

        if (attempts && parseInt(attempts) >= max_request) {
            return res.status(429).json({ message: "Too Many Attempts" });
        }
        await redis.expire(key, max_expire);
        next();

    } catch (error) {
        console.error(error, "Redis Error");
        return res.status(500).json({ message: "Server error. Please try again later" });
    }
}

export default loginRateLimiter;