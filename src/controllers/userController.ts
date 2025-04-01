import { Request, Response, NextFunction } from 'express';
import RegisterUser from '../services/Register.js'
import LoginUser from '../services/Login.js';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const secret = process.env.SECRET_KEY as string;

export const signup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const newUser = await RegisterUser(req.body);
        return res.status(201).json({ message: 'User Created Successfully', id: newUser.id });
    } catch (error) {
        console.error("Error while saving new user:", error);
        const errorMessage = error instanceof Error ? error.message : "Internal Server Error";
        return res.status(500).json({ message: errorMessage });
    }
};


export const signin = async (req: Request, res: Response) => {
    try {
        const user = await LoginUser(req.headers);
        const jwtTokenID = user?.id + "$" + user?.email;
        const token = jwt.sign({ token: jwtTokenID }, secret, { expiresIn: '1m' });
        res.cookie("token", token, { httpOnly: true, secure: true, maxAge: 1000 * 60 * 60 });
        res.status(200).json({ message: "User logged in successfully" });
    } catch (error) {
        console.error(error, "Internal Error");
        const errorMessage = error instanceof Error ? error.message : "Internal Server Error";
        res.status(401).json({ message: errorMessage });
    }
};


