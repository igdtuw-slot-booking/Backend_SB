import express from "express";
import { updateUser , deleteUser , getUser , getallUser, register, login, logout, forgotPassword, resetPassword } from "../controllers/user.js";
import { verifyAdmin, verifyToken, verifyUser, isAuthenticatedUser } from "../utils/verifyToken.js";
//import { register, login} from "../controllers/auth.js";

const router = express.Router();
//import { verifyUser, verifyAdmin } from "../utils/verifyToken.js";         //use verifyadmin verifyuser from verifyToken.js as per the requirement ---like kis function ke liye kya verification needed hai

/*
router.get("/checkauth", verifyToken, (req,res,next)=>{
    res.send("hello user you are logged in");
});

router.get("/checkuser/:id", verifyUser, (req,res,next)=>{
    res.send("hello user you are logged in and can delete your account");
});

router.get("/checkadmin/:id", verifyAdmin, (req,res,next)=>{
    res.send("hello user you are logged in and can delete all account");
});

*/

router.post("/register", register,);
router.post("/login", login);

//UPADATE
router.put("/:id", updateUser);

//DELETE
router.delete("/:id", deleteUser );

//GET
router.get("/i", isAuthenticatedUser, getUser);

//GETALL
router.get("/", getallUser);

//LogOut
router.get("/logout", logout);

//Forgot Password
router.post("/password/forgot", forgotPassword);

//ResetPassword
router.put("/password/reset/:token", resetPassword);


//demo
//router.get("/check/:id", verifyAdmin, (req,res,next) => {
//    res.send("hello admin..u");
//})


export default router
