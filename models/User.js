import mongoose from 'mongoose';
import validator from 'validator';
import crypto from 'crypto';


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
        minLength: [6, "Password should be greater than 6 characters"]
    },
    isAdmin:{
        type: Boolean,                    //while testing.. yea attribute default to false le raha hai but even true type karne pe bhi db mea false store ho raha hai ..so ekk baar dekh lena
        default: false
    },

    resetPasswordToken: String,
    resetPasswordExpire: Date,
    
}, {timestamps: true}
);

UserSchema.methods.matchPassword = async function (password) {
    return await bcrypt.compare(password, this.password);
 };
  
UserSchema.methods.generateToken = function () {
    return jwt.sign({ _id: this._id }, process.env.JWT);
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
