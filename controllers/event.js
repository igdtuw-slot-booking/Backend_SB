import Event from "../models/Event.js";
import User from "../models/User.js";
import ApiFeatures from "../utils/apifeatures.js";
import { createError } from "../utils/error.js";


export const createEvent = async (req,res,next)=>{
    const {
        society,
        eventDesc,
        date,
        time_Start,
        time_End,
        issuer,
        document,
        euipment,
        status,
        venue
    }= req.body;

    //console.log(req.user.id);
    try{
        const event = await Event.create({
            society,
            eventDesc,
            date,
            time_Start,
            time_End,
            issuer,
            document,
            euipment,
            status,
            venue,
            bookedAt: Date.now(),
            user: req.user.id,
        });
    
        res.status(200).json(event)
    } catch(err){
        next(err);
    } 
};

//Update event status --admin
export const updateEvent = async (req,res,next)=>{
    try{
        //const updateEvent = await Event.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
        const updateEvent = await Event.findById(req.params.id);

        if(!updateEvent){
            return next(createError(404, "Event not found with this Id"))
        };

        if(updateEvent.status=== "Approved"){
            return next(createError(400, "You have already approved this event"))
        };
        updateEvent.status = req.body.status;

        if(req.body.status === "Approved"){
            updateEvent.reviewedAt = Date.now();
        };

        await updateEvent.save({ validateBeforeSave: false});
        res.status(200).json(updateEvent)
    } catch(err){
        next(err);
    }
};

//Decline Event by admin ***************don't use for now
export const deleteEvent = async (req,res,next)=>{
    try{
        //await Event.findByIdAndDelete(req.params.id);
        const event = await Event.findById(req.params.id);
        if(!event){
            return next(createError(404, "Event not found with this Id"));
        }
        await event.remove();
        res.status(200).json("Event declined")
    } catch(err){
        next(err);
    }
};

//Get Single Event
export const getSingleEvent = async (req,res,next)=>{
    try{
        const event = await Event.findById(req.params.id).populate("user","email");
        if(!event){
            return next(createError(404, "Event not found with this Id"));
        }
        res.status(200).json(event);
    } catch(err){
        next(err);
    }
};

//Get logged in user Events
export const myEvents = async (req,res,next)=>{
    //console.log(req.user.id);
    const apiFeatures = new ApiFeatures(Event.find({ user: req.user.id }),req.query).filter();
    try{
        const events = await (apiFeatures.query).populate("venue");
        
        res.status(200).json(events);
    } catch(err){
        next(err);
    }
};

export const getallEvent = async (req,res,next)=>{
    const apiFeatures = new ApiFeatures(Event.find(),req.query).filter();
    try{
        const events = await (apiFeatures.query).populate("venue").populate("user");
        res.status(200).json(events);
    } catch(err){
        next(err);
    }
};

export const countByStatus = async (req,res,next)=>{
    const statuses = req.query.status.split(',')
    try{
        const list = await Promise.all(statuses.map(status=>{
            return Event.countDocuments({status:status})
        }))
        res.status(200).json(list);
    } catch(err){
        next(err);
    }
};
