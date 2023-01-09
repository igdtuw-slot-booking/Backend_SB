import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import authRouter from "./routes/auth.js";
import userRouter from "./routes/user.js";
import eventRouter from "./routes/event.js";
import venueRouter from "./routes/venue.js";
import { createError } from "./utils/error.js";
import cookieParser from "cookie-parser";
import cors from "cors";


const app = express();
dotenv.config();

const connect = async () => {
    try {
        await mongoose.connect(process.env.MONGO)
        console.log("MongoDB connected")
    } catch (error) {
        throw error;
    }
};

mongoose.connection.on("disconnected", ()=>{
    console.log("mongoDB disconnected!")
});


//middleware

app.use(cors());
app.use(cookieParser());
app.use(express.json());

app.use("/api/user", userRouter);
app.use("/api/event", eventRouter);
app.use("/api/venue", venueRouter);

app.use((err,req,res,next)=>{
    const errorStatus = err.status || 500 ;
    const errorMessage = err.message || "Something went wrong" ;
/*
    //Wrong Mongodb Id error
    if(err.name === "CastError"){
        const message= `Resource not found. Invalid: ${err.path}`;
        err = createError(400, message)
    }

    //Mongoose duplicate key error
    if(err.code === 11000){
        const message= `Duplicate ${Object.keys(err.keyValue)} Entered`;
        err = createError(400, message)
    }

    //Wrong JWT error
    if(err.name === "JsonWebTokenError"){
        const message= `Json Web Token is Invalid, try again!`;
        err = createError(400, message)
    }

    //JWT Expire Error
    if(err.name === "TokenExpiredError"){
        const message= `Json Web Token is Expired, try again!`;
        err = createError(400, message)
    }
*/
    return res.status(errorStatus).json({
        success:false,
        status: errorStatus,
        message: errorMessage,
        stack: err.stack
    });
});




app.listen(process.env.PORT , ()=>{
    connect()
    console.log("Listening PORT...")
})