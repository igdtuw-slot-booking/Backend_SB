import express from "express";
import { createEvent , updateEvent , deleteEvent , getSingleEvent , getallEvent, countByStatus, myEvents } from "../controllers/event.js";
import { verifyUser, verifyAdmin } from "../utils/verifyToken.js";         //use verifyadmin verifyuser from verifyToken.js as per the requirement ---like kis function ke liye kya verification needed hai

const router = express.Router();

//CREATE
router.post("/", verifyUser, createEvent);

//UPADATE EVENT STATUS --by admin
router.put("/:id", verifyAdmin, updateEvent);

//DECLINE EVENT --by admin
//router.delete("/:id", verifyAdmin, deleteEvent );

//GET LOGGED IN USER EVENTS
router.get("/find/me", verifyUser, myEvents);

//GET
router.get("/find/:id", verifyUser, verifyAdmin, getSingleEvent);


//GETALL
router.get("/", verifyAdmin, getallEvent);

router.get("/countByStatus", countByStatus);



export default router