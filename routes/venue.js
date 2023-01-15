import express from "express";
import { createVenue , updateVenue , deleteVenue , getVenue , getallVenue } from "../controllers/venue.js";
import { verifyUser, isAuthenticatedUser } from "../utils/verifyToken.js";
//import { verifyUser, verifyAdmin } from "../utils/verifyToken.js";         //use verifyadmin verifyuser from verifyToken.js as per the requirement ---like kis function ke liye kya verification needed hai

const router = express.Router();

//CREATE
router.post("/", createVenue);

//UPADATE
router.put("/:id", updateVenue);

//DELETE
router.delete("/:id", deleteVenue );

//GET
router.get("/:id", isAuthenticatedUser, getVenue);

//GETALL
router.get("/", isAuthenticatedUser, getallVenue);


export default router
