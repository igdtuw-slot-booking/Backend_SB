import Venue from "../models/Venue.js"
import ApiFeatures from "../utils/apifeatures.js";

export const createVenue = async (req,res,next)=>{
    const newVenue = new Venue(req.body)
    try{
        const savedVenue = await newVenue.save()
        res.status(200).json(savedVenue)
    } catch(err){
        next(err);
    } 
};

export const updateVenue = async (req,res,next)=>{
    try{
        const updateVenue = await Venue.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
        res.status(200).json(updateVenue)
    } catch(err){
        next(err);
    }
};

export const deleteVenue = async (req,res,next)=>{
    try{
        await Venue.findByIdAndDelete(req.params.id);
        res.status(200).json("Venue deleted")
    } catch(err){
        next(err);
    }
};

export const getVenue = async (req,res,next)=>{
    try{
        const venue = await Venue.findById(req.params.id);
        res.status(200).json(venue);
    } catch(err){
        next(err);
    }
};

export const getallVenue = async (req,res,next)=>{
    const apiFeatures = new ApiFeatures(Venue.find(),req.query).search().filter();
    try{
        const venue = await apiFeatures.query;
        res.status(200).json(venue);
    } catch(err){
        next(err);
    }
};