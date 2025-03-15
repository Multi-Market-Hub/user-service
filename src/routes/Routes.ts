import express from "express";
import { signin, signup, landingPage } from "../controllers/userController";

const router = express.Router();

router.post('/signup', signup);
router.post('/signin', signin);
router.get('/landingPage', landingPage);

export default router;
