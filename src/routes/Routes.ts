import express from "express";
import { signin, signup } from "../controllers/userController";
import loginRateLimiter from '../Middleware/loginRateLimiter';

const router = express.Router();

router.post('/signup', signup);
router.post('/signin', loginRateLimiter, signin);

export default router;
