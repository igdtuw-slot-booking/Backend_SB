import express from "express";
import { createEvent , updateEvent , deleteEvent , getSingleEvent , getallEvent, countByStatus, myEvents, updateEventByUser } from "../controllers/event.js";
import { verifyUser, verifyAdmin, isAuthenticatedUser, authorizeRoles } from "../utils/verifyToken.js";         //use verifyadmin verifyuser from verifyToken.js as per the requirement ---like kis function ke liye kya verification needed hai

const router = express.Router();

//CREATE
router.post("/", isAuthenticatedUser, createEvent);

//UPADATE EVENT STATUS --by admin
router.put("/:id", isAuthenticatedUser, authorizeRoles("admin"), updateEvent);

//DECLINE EVENT --by admin
//router.delete("/:id", verifyAdmin, deleteEvent );

//GET LOGGED IN USER EVENTS
router.get("/find/me", isAuthenticatedUser, myEvents);

//GET
router.get("/find/:id", isAuthenticatedUser, authorizeRoles("admin"), getSingleEvent);


//GETALL
router.get("/", isAuthenticatedUser, authorizeRoles("admin"), getallEvent);

router.get("/countByStatus", countByStatus);

//UPDATE EVENT STATUS TO CANCEL --by user
router.put("/userCancel/:id", isAuthenticatedUser, updateEventByUser);



export default router
