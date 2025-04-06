import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";
import crypto from "crypto";
import transporter from "../config/email.js";
import jwt from "jsonwebtoken";


export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = jwt.sign({ fullName, email, password: hashedPassword }, process.env.JWT_SECRET, {
      expiresIn: "30m",
    });

    const verifyUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your YapYap Email",
      html: `<p>Hello ${fullName},</p>
             <p>Click <a href="${verifyUrl}">here</a> to verify your email.</p>`,
    });

    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    console.error("Error in signup:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const requestVerification = async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailToken = crypto.randomBytes(32).toString("hex");

    // Store temp data in a way you can validate later (e.g. Redis, or JWT token)
    const verificationLink = `${process.env.CLIENT_URL}/verify-email?token=${emailToken}`;

    // You can encode fullName, email, hashedPassword into JWT or save temporarily
    // For now, use JWT:
    const tokenData = jwt.sign({ fullName, email, password: hashedPassword }, process.env.JWT_SECRET, { expiresIn: '' });

    await transporter.sendMail({
      to: email,
      subject: "Verify your YapYap Email",
      html: `<p>Hello ${fullName},</p>
        <p>Click <a href="${verificationLink}">here</a> to verify your email address.</p>`,
    });

    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    console.error("Error in requestVerification:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};


export const verifyEmail = async (req, res) => {
  const { token } = req.query;

  try {
    if (!token) {
      return res.status(400).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { fullName, email, password } = decoded;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      if (existingUser.isVerified) {
        return res.status(400).json({ message: "Email already verified." });
      } else {
        // Clean up unverified duplicate if needed
        await User.deleteOne({ email });
      }
    }

    const user = new User({
      fullName,
      email,
      password,
      isVerified: true,
    });

    await user.save();

    res.status(201).json({ message: "Email verified. Account created successfully!" });
  } catch (error) {
    console.error("Error in verifyEmail:", error.message);
    res.status(400).json({ message: "Invalid or expired verification link." });
  }
};




export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return res.status(401).json({ message: "Please verify your email before logging in." });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    generateToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
    });
  } catch (error) {
    console.log("Error in login controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const logout = (req, res) => {
  try {
    res.cookie("jwt", "", { maxAge: 0 });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.log("Error in logout controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    if (!profilePic) {
      return res.status(400).json({ message: "Profile pic is required" });
    }

    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: uploadResponse.secure_url },
      { new: true }
    );

    res.status(200).json(updatedUser);
  } catch (error) {
    console.log("error in update profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
