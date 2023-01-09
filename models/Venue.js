import mongoose from 'mongoose';

const VenueSchema = new mongoose.Schema({

    name:{
        type: String,
        required: true,
        unique: [true, "Enter Venue"]
    },
    room_no:{
        type: String,
        required: true,
        unique: [true, "Enter Room no."]
    },
    location:{
        type: String,
        required: [true, "Enter Venue Location"]
    },
    capacity:{
        type: Number
    },
    facilities:{
        type: [String]
    },
    images:[
        {
            public_id:{
                type:String,
                required:true
            },
            url:{
                type:String,
                required:true
            }
        }
    ]
    
}
);

export default mongoose.model("Venue", VenueSchema)