import User from "../models/User.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { createError } from "../utils/error.js";
//import sendEmail from "../utils/sendEmail";
import jwt from "jsonwebtoken";
import { sendEmail } from "../utils/sendEmail.js";
import { sendToken } from "../utils/verifyToken.js";
//import { sendToken } from "../utils/verifyToken.js";
//import sendToken from "../utils/verifyToken.js";


export const register = async (req,res,next)=>{
    try{
        const salt= bcrypt.genSaltSync(7);
        const hash= bcrypt.hashSync(req.body.password, salt);

        const newUser = new User({
            ...req.body,
            password: hash
        })
        await newUser.save()
        res.status(200).send("User has been created.")
    }catch(err){
        next(err);
    }
}

export const login = async (req,res,next)=>{
    try{
        const { email, password } = req.body;

    const user = await User.findOne({ email })
      .select("+password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist",
      });
    }

    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Incorrect password",
      });
    }

    const token = await user.generateToken();

    const options = {
      expires: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      httpOnly: true,
    };

    res.status(200).cookie("token", token, options).json({
      success: true,
      user,
      token,
    });
    }catch(error){
      res.status(500).json({
      success: false,
      message: error.message,
      });
    }
};

export const updateUser = async (req,res,next)=>{
    try{
        const updateUser = await User.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
        res.status(200).json(updateUser)
    } catch(err){
        next(err);
    }
};

export const deleteUser = async (req,res,next)=>{
    try{
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json("User deleted")
    } catch(err){
        next(err);
    }
};

export const getUser = async (req,res,next)=>{
    try{
        const user = await User.findById(req.user.id);
        res.status(200).json(user);
    } catch(err){
        next(err);
    }
};

export const getallUser = async (req,res,next)=>{
    try{
        const user = await User.find();
        res.status(200).json(user);
    } catch(err){
        next(err);
    }
};

//Update User Password



//LOGOUT User
export const logout = async (req,res,next)=>{
    try{
        res.cookie("access_token", token, {
            expires: new Date(Date.now()),
            httpOnly: true
        });
        res.status(200).json({
            success: true,
            message: "Logged Out"
        });
    } catch(err){
        next(err);
    }
};

//Forgot Password
export const forgotPassword = async (req,res,next)=>{
        const user = await User.findOne({email:req.body.email});

        if (!user){
            return next(createError(404, "User not found!"));
        }

        //Get ResetPassword Token
        const resetToken = user.getResetPasswordToken();
        await user.save({ validateBeforeSave: false});

        const resetPasswordUrl =  `http://localhost:8877/api/user/password/reset/${resetToken}`;

        const message = `Your password reset token is :-\n\n ${resetPasswordUrl} \n\nIf you have not requested this email then, please ignore it `;

        try{
            await sendEmail({
                email: user.email,
                subject: `SlotBooking Password Recovery`,
                message,
            });

            res.status(200).json({
                success: true,
                message: `Email sent to ${user.email} successfully`,
            })
        }catch(err){
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;

            await user.save({ validateBeforeSave: false});

            return next(createError(500, err));
        }
};

//Reset Password

export const resetPassword = async (req,res,next)=>{
    const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user){
        return next(createError(404, "Reset Password Token is invalid or has been expired"));
    }

    if(req.body.password !== req.body.confirmPassword){
        return next(createError(400, "Password does not password"));
    }

    const salt= bcrypt.genSaltSync(7);
    const hash= bcrypt.hashSync(req.body.password, salt);

    user.password = hash ;
    user.resetPasswordToken = undefined ;
    user.resetPasswordExpire = undefined ;

    await user.save();

    sendToken(user, 200, res);

};


