import { Request, Response } from "express";

import userSchema from "../UserSchema";
import bcrypt from "bcrypt"
import { v4 as uuidv4 } from 'uuid'
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { basicUser, createUser, login } from '../Models/UserModel'
// import { createUser, login } from '@/Models/UserModel'
import { boolean } from "zod";


dotenv.config();


const secret = process.env.SECRET_KEY as string


export const signup = async (req: Request, res: Response) => {
    try {
        const validate = userSchema.safeParse(req.body);
        if (!validate.success) {
            return res.status(400).json({
                msg: "Invalid request data",
            });
        }
        const { firstname, lastname, email, password, isAdmin = false } = validate.data;
        const saltRounds = 10
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const generateUserUUID = uuidv4();
        const newUser = await createUser({
            id: generateUserUUID,
            firstname,
            lastname,
            email,
            password: hashedPassword,
            isAdmin,
        });
        return res.status(201).json({ message: "User Created Successfully", id: newUser.id });
    } catch (error) {
        console.error("Error while saving new user:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

export const signin = async (req: Request, res: Response) => {
    try {
        console.log("Login");

        const { password } = req.body as basicUser
        // Validates whether user exists in the database
        const user = await login(req.body);
        if (user) {
            // Verifies the password sent by the user and the pswd saved in the database
            const checkPassword = await bcrypt.compare(password, user.password);
            if (checkPassword) {
                const jwtTokenID = user.id + user.email
                // why should we use two expiry in token and cookie
                const token = jwt.sign({ id: jwtTokenID }, secret, { expiresIn: '2m' });
                console.log(token);
                res.cookie("token", token, { httpOnly: true, secure: true, maxAge: 1000 * 60 * 60 });
                res.status(200).json({ message: "User Logged in succesfull" });
            }
            else {
                res.status(401).json({
                    message: "Incorrect Password"
                })
            }
        }
        else {
            res.status(404).json({ message: "User not found" })
        }
    } catch (error) {
        console.error(error, "Internal Error");
    }
}


export const landingPage = (req: Request, res: Response) => {
    const token = req.cookies.token;
    try {
        const verifyToken = jwt.verify(token, secret);
        if (verifyToken) {
            res.status(200).json({ message: "Welcome to landing page" });
        }
    } catch (error) {
        res.status(419).json({ message: "JWT expired" });
        console.error(error, "While landing into Home page");
    }
}

