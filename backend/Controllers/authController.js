import User from "../models/User.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// User Register
export const register = async (req, res) => {
   try {
      // Check if user already exists
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
         return res.status(400).json({ success: false, message: "Email already registered!" });
      }

      // Hashing Password (Asynchronous for better performance)
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(req.body.password, salt);

      const newUser = new User({
         username: req.body.username,  
         email: req.body.email,
         password: hash,
         photo: req.body.photo,
      });

      await newUser.save();

      res.status(200).json({ success: true, message: "Successfully Registered!" });
   } catch (error) {
      console.error(error.message);
      res.status(500).json({ success: false, message: error.message || "Failed to Register! Try again." });
      console.log(error.message)
   }
};

// User Login
export const login = async (req, res) => {
   try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });

      // If user doesn't exist
      if (!user) {
         return res.status(404).json({ success: false, message: 'User not found!' });
      }

      // Compare Password
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
         return res.status(401).json({ success: false, message: "Incorrect Email or Password!" });
      }

      const { password: userPassword, role, ...otherDetails } = user.toObject();

      // Ensure JWT Secret Key exists
      if (!process.env.JWT_SECRET_KEY) {
         throw new Error("JWT Secret Key is missing in environment variables.");
      }

      // Create JWT Token
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET_KEY, {
         expiresIn: "15d"
      });

      // Set Token in Browser Cookies
      res.cookie('accessToken', token, {
         httpOnly: true,
         secure: process.env.NODE_ENV === 'production', // Secure cookies in production
         sameSite: 'strict', 
         maxAge: 15 * 24 * 60 * 60 * 1000 // 15 Days
      }).status(200).json({
         success: true,
         message: "Login Successful",
         token,
         data: { ...otherDetails },
         role
      });

   } catch (error) {
      console.error(error.message);
      res.status(500).json({ success: false, message: error.message || "Failed to Login!" });
   }
};
