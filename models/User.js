import mongoose from 'mongoose';
import validator from 'validator';
import crypto from 'crypto';
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";


const UserSchema = new mongoose.Schema({

    email:{
        type: String,
        required: [true, "Enter your EmailID"],
        unique: true,
        validate: [validator.isEmail, "Enter a valid Email"]
    },
    password:{
        type: String,
        required: [true, "Enter your Password"],
        minlength: [6, "Password should be greater than 6 characters"]
    },
    role: {
        type: String,
        default: "user",
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },

    resetPasswordToken: String,
    resetPasswordExpire: Date,
    
}
);

UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
      next();
    }
  
    this.password = await bcrypt.hash(this.password, 10);
});
  
  // JWT TOKEN
UserSchema.methods.getJWTToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT);
};
  
  // Compare Password
  
UserSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

//Generating Password Reset Token
UserSchema.methods.getResetPasswordToken = function () {

    //Generating Tokeb
    const resetToken = crypto.randomBytes(20).toString("hex");
    //Hashing and adding resetPasswordToken to userSchema
    this.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    this.resetPasswordExpire = Date.now() + 15*60*1000;
    return resetToken;
}

export default mongoose.model("User", UserSchema)
