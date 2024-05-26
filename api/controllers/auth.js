import { db } from "../db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = (req, res) => {
    // Check if user already exists
    const q = "SELECT * FROM users WHERE email = ? OR username = ?";

    db.query(q, [req.body.email, req.body.username], (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length) return res.status(409).json("User already exists!");
        
        // Hash password
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(req.body.password, salt);

        // Insert user into database
        const query = "INSERT INTO users (username, email, password) VALUES (?)";
        const values = [req.body.username, req.body.email, hashedPassword];
        
        db.query(query, [values], (err, data) => {
            if (err) return res.json(err);
            res.status(200).json("User created successfully!");
        });
    });
};
 
export const login = (req, res) => {
    // Check if user exists
    const q = "SELECT * FROM users WHERE username = ?";
    db.query(q, [req.body.username], (err, data) => {
        if (err) return res.status(500).json(err);
        if (!data.length) return res.status(404).json("User not found!");

        // Check if password is correct
        const user = data[0];
        const validPassword = bcrypt.compareSync(req.body.password, user.password);
        if (!validPassword) return res.status(400).json("Wrong password!");

        // Create and assign token
        const token = jwt.sign({id: user.id}, "secretkey");
        const { password, ...userInfo } = user;

        res.cookie("access_token", token, {
            httpOnly: true
        }).status(200).json(userInfo);
    });
};

export const logout = (req, res) => {
    res.clearCookie("access_token",{
        sameSite: "none",
        secure: true
    }).status(200).json("Logged out!");
};